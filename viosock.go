//go:build windows
// +build windows

package winio

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Microsoft/go-winio/internal/socket"
)

var afViosock, viosockSupportedErr = getViosockAf()
var viosockInit sync.Once

const (
	VIOSOCK_DEVICE_NAME = "\\??\\Viosock"
	IOCTL_GET_AF        = 0x0801300C
	IOCTL_FIONBIO       = 0x8004667e

	VMADDR_CID_ANY        = 0xffffffff // -1
	VMADDR_CID_HYPERVISOR = 0
	// VMADDR_CID_LOCAL is not supported
	VMADDR_CID_HOST = 2
)

func getViosockAf() (uint16, error) {
	utf16name, err := syscall.UTF16FromString(VIOSOCK_DEVICE_NAME)
	if err != nil {
		return 0, err
	}

	var nullHandle windows.Handle
	handle, err := windows.CreateFile(&utf16name[0], windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, nullHandle)
	if err != nil {
		return 0, err
	}

	var af uint32
	var returned uint32
	err = windows.DeviceIoControl(handle, IOCTL_GET_AF, nil, 0, (*byte)(unsafe.Pointer(&af)), (uint32)(unsafe.Sizeof(af)), &returned, nil)
	if err != nil {
		return 0, err
	}
	windows.Close(handle)
	return uint16(af), nil
}

type ViosockAddr struct {
	Port uint32
	Cid  uint32
}

type rawViosockAddr struct {
	Family uint16
	_      uint16
	Port   uint32 // host byte order
	Cid    uint32 // host byte order
}

var _ socket.RawSockaddr = &rawViosockAddr{}

// Network returns the address's network name, "hvsock".
func (*ViosockAddr) Network() string {
	return "viovsock"
}

func (addr *ViosockAddr) String() string {
	return fmt.Sprintf("%s:%d", addr.Cid, addr.Port)
}

func (addr *ViosockAddr) raw() rawViosockAddr {
	return rawViosockAddr{
		Family: afViosock,
		Port:   addr.Port,
		Cid:    addr.Cid,
	}
}

func (addr *ViosockAddr) fromRaw(raw *rawViosockAddr) {
	addr.Cid = raw.Cid
	addr.Port = raw.Port
}

// Sockaddr returns a pointer to and the size of this struct.
//
// Implements the [socket.RawSockaddr] interface, and allows use in
// [socket.Bind] and [socket.ConnectEx].
func (r *rawViosockAddr) Sockaddr() (unsafe.Pointer, int32, error) {
	p := unsafe.Pointer(r)
	s := unsafe.Slice((*byte)(p), unsafe.Sizeof(rawViosockAddr{}))
	fmt.Println("Using addr: ", hex.EncodeToString((s)))
	return unsafe.Pointer(r), int32(unsafe.Sizeof(rawViosockAddr{})), nil
}

// Sockaddr interface allows use with `sockets.Bind()` and `.ConnectEx()`.
func (r *rawViosockAddr) FromBytes(b []byte) error {
	n := int(unsafe.Sizeof(rawViosockAddr{}))

	if len(b) < n {
		return fmt.Errorf("got %d, want %d: %w", len(b), n, socket.ErrBufferSize)
	}

	copy(unsafe.Slice((*byte)(unsafe.Pointer(r)), n), b[:n])
	if r.Family != uint16(afViosock) {
		return fmt.Errorf("got %d, want %d: %w", r.Family, afViosock, socket.ErrAddrFamily)
	}

	return nil
}

// ViosockListener is a socket listener for the AF_HYPERV address family.
type ViosockListener struct {
	sock *win32File
	addr ViosockAddr
}

var _ net.Listener = &ViosockListener{}

// ViosockConn is a connected socket of the AF_HYPERV address family.
type ViosockConn struct {
	sock          *win32File
	local, remote ViosockAddr
}

var _ net.Conn = &ViosockConn{}

func initViosock() {
	if viosockSupportedErr != nil {
		fmt.Println(viosockSupportedErr)
		panic("Address family is not supported")
	}
}

func newVioSocket() (*win32File, error) {
	viosockInit.Do(initViosock)
	fd, err := syscall.Socket(int(afViosock), syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}

	f, err := makeWin32File(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	f.socket = true
	return f, nil
}

// ListenViosock listens for connections on the specified hvsock address.
func ListenViosock(addr *ViosockAddr) (_ *ViosockListener, err error) {
	l := &ViosockListener{addr: *addr}
	fmt.Println("Creating socket")
	sock, err := newVioSocket()
	fmt.Println("Socket Created")
	if err != nil {
		fmt.Println("failed to create")
		return nil, l.opErr("listen", err)
	}
	sa := addr.raw()
	fmt.Println("Binding Socket")
	fmt.Println("sock fd:", sock.handle)
	err = socket.Bind(windows.Handle(sock.handle), &sa)
	if err != nil {
		fmt.Println("failed to bind")
		return nil, l.opErr("listen", os.NewSyscallError("socket", err))
	}
	fmt.Println("Socket bound")
	fmt.Println("Listening socket")
	err = syscall.Listen(sock.handle, 16)
	if err != nil {
		fmt.Println("failed to listen")
		return nil, l.opErr("listen", os.NewSyscallError("listen", err))
	}
	fmt.Println("Socket listened")
	return &ViosockListener{sock: sock, addr: *addr}, nil
}

func (l *ViosockListener) opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "viosock", Addr: &l.addr, Err: err}
}

// Addr returns the listener's network address.
func (l *ViosockListener) Addr() net.Addr {
	return &l.addr
}

// Accept waits for the next connection and returns it.
func (l *ViosockListener) Accept() (_ net.Conn, err error) {
	sock, err := newVioSocket()
	if err != nil {
		return nil, l.opErr("accept", err)
	}
	defer func() {
		if sock != nil {
			sock.Close()
		}
	}()
	c, err := l.sock.prepareIO()
	if err != nil {
		return nil, l.opErr("accept", err)
	}
	defer l.sock.wg.Done()

	// AcceptEx, per documentation, requires an extra 16 bytes per address.
	//
	// https://docs.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-acceptex
	const addrlen = uint32(16 + unsafe.Sizeof(rawViosockAddr{}))
	var addrbuf [addrlen * 2]byte

	var bytes uint32
	err = syscall.AcceptEx(l.sock.handle, sock.handle, &addrbuf[0], 0 /*rxdatalen*/, addrlen, addrlen, &bytes, &c.o)
	if _, err = l.sock.asyncIO(c, nil, bytes, err); err != nil {
		return nil, l.opErr("accept", os.NewSyscallError("acceptex", err))
	}

	conn := &ViosockConn{
		sock: sock,
	}
	// The local address returned in the AcceptEx buffer is the same as the Listener socket's
	// address. However, the service GUID reported by GetSockName is different from the Listeners
	// socket, and is sometimes the same as the local address of the socket that dialed the
	// address, with the service GUID.Data1 incremented, but othertimes is different.
	// todo: does the local address matter? is the listener's address or the actual address appropriate?
	conn.local.fromRaw((*rawViosockAddr)(unsafe.Pointer(&addrbuf[0])))
	conn.remote.fromRaw((*rawViosockAddr)(unsafe.Pointer(&addrbuf[addrlen])))

	// initialize the accepted socket and update its properties with those of the listening socket
	if err = windows.Setsockopt(windows.Handle(sock.handle),
		windows.SOL_SOCKET, windows.SO_UPDATE_ACCEPT_CONTEXT,
		(*byte)(unsafe.Pointer(&l.sock.handle)), int32(unsafe.Sizeof(l.sock.handle))); err != nil {
		return nil, conn.opErr("accept", os.NewSyscallError("setsockopt", err))
	}

	sock = nil
	return conn, nil
}

// Close closes the listener, causing any pending Accept calls to fail.
func (l *ViosockListener) Close() error {
	return l.sock.Close()
}

// ViosockDialer configures and dials a Hyper-V Socket (ie, [ViosockConn]).
type ViosockDialer struct {
	// Deadline is the time the Dial operation must connect before erroring.
	Deadline time.Time

	// Retries is the number of additional connects to try if the connection times out, is refused,
	// or the host is unreachable
	Retries uint

	// RetryWait is the time to wait after a connection error to retry
	RetryWait time.Duration

	rt *time.Timer // redial wait timer
}

// Dial the Hyper-V socket at addr.
//
// See [ViosockDialer.Dial] for more information.
func Dial(ctx context.Context, addr *ViosockAddr) (conn *ViosockConn, err error) {
	return (&ViosockDialer{}).Dial(ctx, addr)
}

// Dial attempts to connect to the Hyper-V socket at addr, and returns a connection if successful.
// Will attempt (ViosockDialer).Retries if dialing fails, waiting (ViosockDialer).RetryWait between
// retries.
//
// Dialing can be cancelled either by providing (ViosockDialer).Deadline, or cancelling ctx.
func (d *ViosockDialer) Dial(ctx context.Context, addr *ViosockAddr) (conn *ViosockConn, err error) {
	op := "dial"
	// create the conn early to use opErr()
	conn = &ViosockConn{
		remote: *addr,
	}

	if !d.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, d.Deadline)
		defer cancel()
	}

	// preemptive timeout/cancellation check
	if err = ctx.Err(); err != nil {
		return nil, conn.opErr(op, err)
	}

	sock, err := newVioSocket()
	if err != nil {
		return nil, conn.opErr(op, err)
	}
	defer func() {
		if sock != nil {
			sock.Close()
		}
	}()

	sa := addr.raw()
	err = socket.Bind(windows.Handle(sock.handle), &sa)
	if err != nil {
		return nil, conn.opErr(op, os.NewSyscallError("bind", err))
	}

	c, err := sock.prepareIO()
	if err != nil {
		return nil, conn.opErr(op, err)
	}
	defer sock.wg.Done()
	var bytes uint32
	for i := uint(0); i <= d.Retries; i++ {
		err = socket.ConnectEx(
			windows.Handle(sock.handle),
			&sa,
			nil, // sendBuf
			0,   // sendDataLen
			&bytes,
			(*windows.Overlapped)(unsafe.Pointer(&c.o)))
		_, err = sock.asyncIO(c, nil, bytes, err)
		if i < d.Retries && canRedial(err) {
			if err = d.redialWait(ctx); err == nil {
				continue
			}
		}
		break
	}
	if err != nil {
		return nil, conn.opErr(op, os.NewSyscallError("connectex", err))
	}

	// update the connection properties, so shutdown can be used
	if err = windows.Setsockopt(
		windows.Handle(sock.handle),
		windows.SOL_SOCKET,
		windows.SO_UPDATE_CONNECT_CONTEXT,
		nil, // optvalue
		0,   // optlen
	); err != nil {
		return nil, conn.opErr(op, os.NewSyscallError("setsockopt", err))
	}

	// get the local name
	var sal rawViosockAddr
	err = socket.GetSockName(windows.Handle(sock.handle), &sal)
	if err != nil {
		return nil, conn.opErr(op, os.NewSyscallError("getsockname", err))
	}
	conn.local.fromRaw(&sal)

	// one last check for timeout, since asyncIO doesn't check the context
	if err = ctx.Err(); err != nil {
		return nil, conn.opErr(op, err)
	}

	conn.sock = sock
	sock = nil

	return conn, nil
}

// redialWait waits before attempting to redial, resetting the timer as appropriate.
func (d *ViosockDialer) redialWait(ctx context.Context) (err error) {
	if d.RetryWait == 0 {
		return nil
	}

	if d.rt == nil {
		d.rt = time.NewTimer(d.RetryWait)
	} else {
		// should already be stopped and drained
		d.rt.Reset(d.RetryWait)
	}

	select {
	case <-ctx.Done():
	case <-d.rt.C:
		return nil
	}

	// stop and drain the timer
	if !d.rt.Stop() {
		<-d.rt.C
	}
	return ctx.Err()
}

// assumes error is a plain, unwrapped syscall.Errno provided by direct syscall.
func canRedial(err error) bool {
	//nolint:errorlint // guaranteed to be an Errno
	switch err {
	case windows.WSAECONNREFUSED, windows.WSAENETUNREACH, windows.WSAETIMEDOUT,
		windows.ERROR_CONNECTION_REFUSED, windows.ERROR_CONNECTION_UNAVAIL:
		return true
	default:
		return false
	}
}

func (conn *ViosockConn) opErr(op string, err error) error {
	// translate from "file closed" to "socket closed"
	if errors.Is(err, ErrFileClosed) {
		err = socket.ErrSocketClosed
	}
	return &net.OpError{Op: op, Net: "viosock", Source: &conn.local, Addr: &conn.remote, Err: err}
}

func (conn *ViosockConn) Read(b []byte) (int, error) {
	c, err := conn.sock.prepareIO()
	if err != nil {
		return 0, conn.opErr("read", err)
	}
	defer conn.sock.wg.Done()
	buf := syscall.WSABuf{Buf: &b[0], Len: uint32(len(b))}
	var flags, bytes uint32
	err = syscall.WSARecv(conn.sock.handle, &buf, 1, &bytes, &flags, &c.o, nil)
	n, err := conn.sock.asyncIO(c, &conn.sock.readDeadline, bytes, err)
	if err != nil {
		var eno windows.Errno
		if errors.As(err, &eno) {
			err = os.NewSyscallError("wsarecv", eno)
		}
		return 0, conn.opErr("read", err)
	} else if n == 0 {
		err = io.EOF
	}
	return n, err
}

func (conn *ViosockConn) Write(b []byte) (int, error) {
	t := 0
	for len(b) != 0 {
		n, err := conn.write(b)
		if err != nil {
			return t + n, err
		}
		t += n
		b = b[n:]
	}
	return t, nil
}

func (conn *ViosockConn) write(b []byte) (int, error) {
	c, err := conn.sock.prepareIO()
	if err != nil {
		return 0, conn.opErr("write", err)
	}
	defer conn.sock.wg.Done()
	buf := syscall.WSABuf{Buf: &b[0], Len: uint32(len(b))}
	var bytes uint32
	err = syscall.WSASend(conn.sock.handle, &buf, 1, &bytes, 0, &c.o, nil)
	n, err := conn.sock.asyncIO(c, &conn.sock.writeDeadline, bytes, err)
	if err != nil {
		var eno windows.Errno
		if errors.As(err, &eno) {
			err = os.NewSyscallError("wsasend", eno)
		}
		return 0, conn.opErr("write", err)
	}
	return n, err
}

// Close closes the socket connection, failing any pending read or write calls.
func (conn *ViosockConn) Close() error {
	return conn.sock.Close()
}

func (conn *ViosockConn) IsClosed() bool {
	return conn.sock.IsClosed()
}

// shutdown disables sending or receiving on a socket.
func (conn *ViosockConn) shutdown(how int) error {
	if conn.IsClosed() {
		return socket.ErrSocketClosed
	}

	err := syscall.Shutdown(conn.sock.handle, how)
	if err != nil {
		// If the connection was closed, shutdowns fail with "not connected"
		if errors.Is(err, windows.WSAENOTCONN) ||
			errors.Is(err, windows.WSAESHUTDOWN) {
			err = socket.ErrSocketClosed
		}
		return os.NewSyscallError("shutdown", err)
	}
	return nil
}

// CloseRead shuts down the read end of the socket, preventing future read operations.
func (conn *ViosockConn) CloseRead() error {
	err := conn.shutdown(syscall.SHUT_RD)
	if err != nil {
		return conn.opErr("closeread", err)
	}
	return nil
}

// CloseWrite shuts down the write end of the socket, preventing future write operations and
// notifying the other endpoint that no more data will be written.
func (conn *ViosockConn) CloseWrite() error {
	err := conn.shutdown(syscall.SHUT_WR)
	if err != nil {
		return conn.opErr("closewrite", err)
	}
	return nil
}

// LocalAddr returns the local address of the connection.
func (conn *ViosockConn) LocalAddr() net.Addr {
	return &conn.local
}

// RemoteAddr returns the remote address of the connection.
func (conn *ViosockConn) RemoteAddr() net.Addr {
	return &conn.remote
}

// SetDeadline implements the net.Conn SetDeadline method.
func (conn *ViosockConn) SetDeadline(t time.Time) error {
	// todo: implement `SetDeadline` for `win32File`
	if err := conn.SetReadDeadline(t); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	if err := conn.SetWriteDeadline(t); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (conn *ViosockConn) SetReadDeadline(t time.Time) error {
	return conn.sock.SetReadDeadline(t)
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (conn *ViosockConn) SetWriteDeadline(t time.Time) error {
	return conn.sock.SetWriteDeadline(t)
}
