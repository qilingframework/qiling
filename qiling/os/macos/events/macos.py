
#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes, socket, struct
 
 
from functools import wraps
from unicorn.x86_const import *
from unicorn import UcError, UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

from qiling.os.macos.structs import *
from qiling.os.macos.utils import gen_stub_code
from .macos_structs import *


class QlMacOSEv:
    def __init__(self, ql, ev_type, ev_name, ev_obj, ev_obj_idx=-1, protocol=None):
        self.ql = ql
        self.type = ev_type
        self.name = ev_name
        self.event = ev_obj
        self.params = []
        self.ev_index = ev_obj_idx
        self.protocol = protocol

    def set_params(self, params):
        if self.ev_index != -1 and self.event is not None:
            self.params = params[:]
            self.params.insert(self.ev_index, self.event.base)
        else:
            self.params = params[:]

    def dump(self):
        self.ql.log.info("[*] Dumping object: %s with type %d" % (self.name, self.type.value))
        for field in self.event._fields_:
            if isinstance(getattr(self.event, field[0]), POINTER64):
                self.ql.log.info("%s: 0x%x" % (field[0], getattr(self.event, field[0]).value))
            elif isinstance(getattr(self.event, field[0]), int):
                self.ql.log.info("%s: %d" % (field[0], getattr(self.event, field[0])))
            elif isinstance(getattr(self.event, field[0]), bytes):
                self.ql.log.info("%s: %s" % (field[0], getattr(self.event, field[0]).decode()))

def init_ev_ctx(f):
    @wraps(f)
    def wrapper(self, *args, **kw):
        if self.label is None:
            label_addr = self.ql.os.heap.alloc(ctypes.sizeof(label_t))
            self.label = label_t(self.ql, label_addr)
            self.label.l_flags = 1
            self.label.updateToMem()

        if self.cred is None:
            cred_addr = self.ql.os.heap.alloc(ctypes.sizeof(ucred_t))
            self.cred = ucred_t(self.ql, cred_addr)
            self.cred.cr_ref = 2
            pyarr = [20, 12, 61, 79, 80, 81, 98, 33, 100, 204, 250, 395, 398, 399, 701, 0]
            self.cred.cr_posix = ucred_t.posix_cred_t(
                501,
                501,
                501,
                15,
                (ctypes.c_uint32 * len(pyarr))(*pyarr),
                20,
                20,
                501,
                2)
            self.cred.cr_label = POINTER64(self.label.base)
            self.cred.updateToMem()

        if self.vnode is None:
            tmp_addr = self.ql.os.heap.alloc(ctypes.sizeof(vnode_t))
            self.vnode = vnode_t(self.ql, tmp_addr)
            tmp_name = self.ql.os.heap.alloc(len(self.current_proc))
            self.ql.mem.write(tmp_name, self.current_proc.encode())
            self.vnode.v_name = POINTER64(tmp_name)
            self.vnode.updateToMem()

        return f(self, *args, **kw)
    return wrapper

class QlMacOSEvManager:
    def __init__(self, ql):
        self.ql = ql
        self.callbacks = {}
        self.jobs = []

        self.src_host = "192.168.13.37"
        self.src_port = socket.htons(1337)
        self.src_mac = b"\xba\xbe\xc0\xde\xbe\x57"
        
        self.dst_host = "10.2.13.38"
        self.dst_port = socket.htons(1338)
        self.dst_mac = b"\xba\xbe\xfe\xed\xfa\xce"

        self.current_proc = self.ql.argv[0]
        self.cred = None
        self.label = None
        self.vnode = None

        self.target_pid = 0xdeadbeef

        self.my_procs = []
        self.allproc = None

        self.map_fd = {}
        self.ipf_cookie = {}
        self.sockets = []

        self.deadcode = None

    def add_process(self, pid, name):
        for p in self.my_procs:
            if p.p_pid == pid:
                self.ql.log.info("Duplicated process")
                return

        cur_proc_addr = self.ql.os.heap.alloc(ctypes.sizeof(proc_t))
        cur_proc = proc_t(self.ql, cur_proc_addr)
        cur_proc.p_pid = pid
        cur_proc.p_ppid = 1
        cur_proc.p_pgrpid = pid
        cur_proc.p_flag = 0x00000004 # 64 bit proccess
        cur_proc.p_uid = 0
        cur_proc.p_gid = 0
        cur_proc.p_ruid = 0
        cur_proc.p_rgid = 0
        cur_proc.p_svuid = 0
        cur_proc.p_svgid = 0
        p_comm = name.encode() + b"\x00" * (17 - len(name))
        cur_proc.p_comm = p_comm
        p_name = p_comm + b"\x00" * 16
        cur_proc.p_name = p_name

        cred_addr = self.ql.os.heap.alloc(ctypes.sizeof(ucred_t))
        cur_proc.p_ucred = POINTER64(cred_addr)

        cur_proc.updateToMem()

        if len(self.my_procs) == 0:
            self.allproc.lh_first = POINTER64(cur_proc_addr)
            self.allproc.updateToMem()
            self.my_procs.append(cur_proc)
        else:
            prev_proc = self.my_procs[-1]
            prev_proc.p_list.le_next = POINTER64(cur_proc_addr)
            cur_proc.p_list.le_prev = POINTER64(prev_proc.base)
            self.my_procs.append(cur_proc)
            cur_proc.updateToMem()
            prev_proc.updateToMem()

    def proc_find(self, pid):
        for p in self.my_procs:
            if p.p_pid == pid:
                return p
        return None

    def set_allproc(self, allprocs_addr):
        self.my_procs.clear()
        self.allproc = list_head(self.ql, allprocs_addr).loadFromMem()

    def set_target_pid(self, target_pid):
        self.target_pid = target_pid

    def set_proc(self, name):
        self.current_proc = name

    def set_src_host(self, host):
        self.src_host = host

    def set_src_port(self, port):
        self.src_port = htons(port)

    def set_src_mac(self, mac):
        self.src_mac = mac

    def set_dst_host(self, host):
        self.dst_host = host

    def set_dst_port(self, port):
        self.dst_port = htons(port)

    def set_dst_mac(self, mac):
        self.dst_mac = mac

    def register(self, func_addr, ev_name, ev_type, ev_obj=None, idx=-1, protocol=None):
        ev_name = ev_name.decode()
        event = QlMacOSEv(self.ql, ev_type, ev_name, ev_obj, idx, protocol)
        if event in self.callbacks:
            self.callbacks[event].append(func_addr)
        else:
            self.callbacks[event] = [func_addr]

    def deregister(self, ev_name, keyword=b""):
        found = self.get_events_by_name(ev_name, keyword)
        for f in found:
            del self.callbacks[f]

    def get_events_by_name(self, ev_name, keyword=b""):
        found = []
        for ev, cb in self.callbacks.items():
            if (len(ev_name) > 0 and ev.name == ev_name) or (len(keyword) > 0 and keyword in ev.name):
                found.append(ev)
        return found

    def emit(self, ev_name, ev_type, params):
        found = self.get_event_by_name_and_type(ev_name, ev_type)
        if found is None:
            self.ql.log.info("No callbacks found for (%s, %s)" % (ev_name, ev_type))
            return

        found.set_params(params)
        for cb in self.callbacks[found]:
            if self.ql.os.RUN is True:
                self.ql.stack_push(gen_stub_code(self.ql, found.params, cb))
            else:
                self.jobs.append((cb, found))

    def emit_by_type(self, ev_type, params, ins_cookie=False):
        found = self.get_events_by_type(ev_type)
        for ev in found:
            if ins_cookie is True and ev.name in self.ipf_cookie:
                params[0] = self.ipf_cookie[ev.name]
            ev.set_params(params)
            for cb in self.callbacks[ev]:
                if self.ql.os.RUN is True:
                    self.ql.stack_push(gen_stub_code(self.ql, ev.params, cb))
                else:
                    self.jobs.append((cb, ev))

    def emit_by_type_and_proto(self, ev_type, protocol, params):
        found = self.get_events_by_type_and_proto(ev_type, protocol)
        for ev in found:
            ev.set_params(params)
            for cb in self.callbacks[ev]:
                if self.ql.os.RUN is True:
                    self.ql.stack_push(gen_stub_code(self.ql, ev.params, cb))
                else:
                    self.jobs.append((cb, ev))

    def get_events_by_type_and_proto(self, ev_type, protocol):
        found = []
        for ev, cb in self.callbacks.items():
            if ev.type == ev_type and ev.protocol == protocol:
                found.append(ev)
        return found

    def get_events_by_type(self, ev_type):
        found = []
        for ev, cb in self.callbacks.items():
            if ev.type == ev_type:
                found.append(ev)
        return found

    def get_event_by_name_and_type(self, ev_name, ev_type):
        found = None
        for ev, cb in self.callbacks.items():
            if ev.name == ev_name and ev.type == ev_type:
                found = ev
                break
        return found

    def trigger(self):
        reg_list = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
        for cb, ev in self.jobs:
            params = ev.params
            remains = 0
            if len(params) <= 6:
                for idx, p in enumerate(params):
                    self.ql.reg.write(reg_list[idx], p)
            else:
                for idx, p in enumerate(params[:6]):
                    self.ql.reg.write(reg_list[idx], p)
                remains = len(params) - 6
                for i in range(remains):
                    self.ql.stack_push(params[6 + i])
            # TODO: Too many kind of callbacks to find saved rip, lmao
            self.ql.os.savedrip=self.deadcode
            self.ql.run(begin=cb)

        self.jobs.clear()

    def clear_heap(self):
        self.ql.os.heap.clear()

    @init_ev_ctx
    def sysctlbyname(self, name, namelen, oldp, oldlenp, new, newlen):
        uap_addr = self.ql.os.heap.alloc(ctypes.sizeof(sysctlbyname_args_t))
        uap = sysctlbyname_args_t(self.ql, uap_addr)

        uap.name = POINTER64(name)
        uap.namelen = namelen
        uap.oldp = POINTER64(oldp)
        uap.oldlenp = POINTER64(oldlenp)
        uap.new = POINTER64(new)
        uap.newlen = newlen
        uap.updateToMem()

        self.ql.reg.rdi = self.proc_find(0x1337).base
        self.ql.reg.rsi = uap_addr # uap
        self.ql.reg.rdx = 0 # unused retval
        self.ql.os.savedrip=self.deadcode
        self.ql.run(self.ql.loader.kernel_extrn_symbols_detail[b"_sysctlbyname"]["n_value"])

    @init_ev_ctx
    def ctl_connect(self, nke_name, unitinfo=0):
        nke_addr = self.ql.os.heap.alloc(ctypes.sizeof(sockaddr_ctl_t))
        nke_obj = sockaddr_ctl_t(self.ql, nke_addr)

        nke_obj.sc_len = ctypes.sizeof(sockaddr_ctl_t)
        nke_obj.sc_family = 32 # AF_SYSTEM
        nke_obj.ss_sysaddr = 2 # AF_SYS_CONTROL
        nke_obj.sc_id = 0x1337
        nke_obj.sc_unit = 2
        nke_obj.updateToMem()

        # static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
        self.emit(nke_name, MacOSEventType.EV_CTL_CONNECT, [nke_addr, unitinfo])

    @init_ev_ctx
    def ctl_disconnect(self, nke_name, unitinfo=0):

        # static int ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
        self.emit(nke_name, MacOSEventType.EV_CTL_DISCONNECT, [2, unitinfo])

    @init_ev_ctx
    def ctl_send(self, nke_name, data):
        buf = self.ql.os.heap.alloc(len(data))
        self.ql.mem.write(buf, data.encode())
        mbuf_addr = self.ql.os.heap.alloc(ctypes.sizeof(mbuf_t))
        mbuf = mbuf_t(self.ql, mbuf_addr)
        mbuf.m_hdr.mh_len = len(data)
        mbuf.m_hdr.mh_data = POINTER64(buf)
        mbuf.m_hdr.mh_flags = 2
        mbuf.updateToMem()

        # static int ctl_send(kern_ctl_ref ctlref, unsigned int unit, void *userdata, mbuf_t m, int flags)
        self.emit(nke_name, MacOSEventType.EV_CTL_SEND, [2, 0, mbuf_addr, 2])

    @init_ev_ctx
    def ctl_setopt(self, nke_name, opt, data, unitinfo=0):
        sopt_val = self.ql.os.heap.alloc(len(data))
        self.ql.mem.write(sopt_val, data.encode())

        # static int ctl_setopt(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
        self.emit(nke_name, MacOSEventType.EV_CTL_SETOPT, [2, unitinfo, opt, sopt_val, len(data)])

    @init_ev_ctx
    def ctl_getopt(self, nke_name, opt, data, unitinfo=0):
        sopt_val = self.ql.os.heap.alloc(len(data))
        self.ql.mem.write(sopt_val, data.encode())

        # static int ctl_getopt(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len)
        self.emit(nke_name, MacOSEventType.EV_CTL_GETOPT, [2, unitinfo, opt, sopt_val, len(data)])

    @init_ev_ctx
    def net_new_socket(self, protocol, cookie_holder=0):
        if cookie_holder == 0:
            cookie_holder = self.ql.os.heap.alloc(8)
        # sflt_attach(void **cookie, socket_t socket)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_ATTACH, protocol.value, [cookie_holder, 0])
        self.trigger()
        cookie = struct.unpack("<Q", self.ql.mem.read(cookie_holder, 8))[0]
        return cookie

    def gen_sock(self, host, port):
        # Currently support only AF_INET
        sock_addr = self.ql.os.heap.alloc(ctypes.sizeof(sockaddr_in_t))
        sock = sockaddr_in_t(self.ql, sock_addr)

        sock.sin_len = ctypes.sizeof(sockaddr_in_t)
        sock.sin_family = 2 # AF_INET
        sock.sin_port = port
        sock.sin_addr = sockaddr_in_t.in_addr_t(struct.unpack("I", socket.inet_aton(host))[0])
        sock.updateToMem()
        return sock

    def clear_socks(self):
        self.sockets.clear()

    @init_ev_ctx
    def net_connect_out(self, protocol):
        from_sock = self.gen_sock(self.src_host, self.src_port)
        from_idx = len(self.sockets)
        self.sockets.append(from_sock)

        to_sock = self.gen_sock(self.dst_host, self.dst_port)
        to_idx = len(self.sockets)
        self.sockets.append(to_sock)

        # sflt_connect_out(void *cookie, socket_t socket, const struct sockaddr *to)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_CONNECT_OUT, protocol.value, [cookie, from_idx, to_sock.base])

        # sflt_notify(void *cookie, socket_t socket, sflt_event_t event, void *param)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_NOTIFY_BOUND, protocol.value, [cookie, from_idx, SocketEvent.BOUND.value - base_event_socket, 0])

        # sflt_notify(void *cookie, socket_t socket, sflt_event_t event, void *param)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_NOTIFY_CONNECTING, protocol.value, [cookie, from_idx, SocketEvent.CONNECTING.value - base_event_socket, 0])

        # sflt_notify(void *cookie, socket_t socket, sflt_event_t event, void *param)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_NOTIFY_CONNECTED, protocol.value, [cookie, to_idx, SocketEvent.CONNECTED.value - base_event_socket, 0])

        return from_idx, to_idx

    @init_ev_ctx
    def net_connect_in(self, cookie, protocol):
        from_sock = self.gen_sock(self.src_host, self.src_port)
        from_idx = len(self.sockets)
        self.sockets.append(from_sock)

        to_sock = self.gen_sock(self.dst_host, self.dst_port)
        to_idx = len(self.sockets)
        self.sockets.append(to_sock)

        # sflt_bind(void *cookie, socket_t socket, const struct sockaddr *to)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_BIND, protocol.value, [cookie, from_idx, from_sock.base])

        # sflt_notify(void *cookie, socket_t socket, sflt_event_t event, void *param)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_NOTIFY_BOUND, protocol.value, [cookie, from_idx, SocketEvent.BOUND.value - base_event_socket, 0])

        # sflt_listen(void *cookie, socket_t socket)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_LISTEN, protocol.value, [cookie, from_idx])

        # sflt_connect_in(void *cookie, socket_t socket, const struct sockaddr *to)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_CONNECT_IN, protocol.value, [cookie, from_idx, to_sock.base])

        # sflt_notify(void *cookie, socket_t socket, sflt_event_t event, void *param)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_NOTIFY_CONNECTED, protocol.value, [cookie, to_idx, SocketEvent.CONNECTING.value - base_event_socket, 0])

        return from_idx, to_idx

    @init_ev_ctx
    def net_disconnect(self, cookie, so, protocol):
        # sflt_detach_ipv4(void *cookie, socket_t socket)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_DETACH, protocol.value, [cookie, 0])
        # ipf_detach(void* cookie)
        self.emit_by_type(MacOSEventType.EV_IPF_DETACH, [cookie])

        # sflt_notify(void *cookie, socket_t socket, sflt_event_t event, void *param)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_NOTIFY_CLOSING, protocol.value, [cookie, so, SocketEvent.CLOSING.value - base_event_socket, 0])

        # sflt_notify(void *cookie, socket_t socket, sflt_event_t event, void *param)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_NOTIFY_DISCONNECTING, protocol.value, [cookie, so, SocketEvent.DISCONNECTING.value - base_event_socket, 0])

        # sflt_notify(void *cookie, socket_t socket, sflt_event_t event, void *param)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_NOTIFY_DISCONNECTED, protocol.value, [cookie, so, SocketEvent.DISCONNECTED.value - base_event_socket, 0])

    @init_ev_ctx
    def net_set_option(self, cookie, so, data, protocol):
        sopt_val = self.ql.os.heap.alloc(len(data))
        sopt_addr = self.ql.os.heap.alloc(ctypes.sizeof(sockopt_t))
        sopt = sockopt_t(self.ql, sopt_addr)
        sopt.sopt_val = POINTER64(sopt_val)
        sopt.updateToMem()

        # sflt_set_option(void *cookie, socket_t socket, sockopt_t option)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_SETOPTION, protocol.value, [cookie, so, sopt_addr])

    @init_ev_ctx
    def net_get_option(self, cookie, so, data, protocol):
        sopt_val = self.ql.os.heap.alloc(len(data))
        sopt_addr = self.ql.os.heap.alloc(ctypes.sizeof(sockopt_t))
        sopt = sockopt_t(self.ql, sopt_addr)
        sopt.sopt_val = POINTER64(sopt_val)
        sopt.updateToMem()

        # sflt_get_option(void *cookie, socket_t socket, sockopt_t option)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_GETOPTION, protocol.value, [cookie, so, sopt_addr])

    @init_ev_ctx
    def net_send(self, cookie, from_idx, to_idx, protocol, last_header, data):
        from scapy.all import Ether, IP, TCP, Raw, ICMP

        ether = Ether(src=self.src_mac, dst=self.dst_mac)
        ip = IP(src=self.src_host, dst=self.dst_host)
        packet_header = (ether).build()
        packet = (ether/ip/last_header/Raw(load=data)).build()

        packet_addr = self.ql.os.heap.alloc(len(packet))
        self.ql.mem.write(packet_addr, packet)

        mbuf_addr = self.ql.os.heap.alloc(ctypes.sizeof(mbuf_t))
        mbuf = mbuf_t(self.ql, mbuf_addr)
        mbuf.m_hdr.mh_len = len(packet) - len(packet_header)
        mbuf.m_hdr.mh_data = POINTER64(packet_addr + len(packet_header))
        mbuf.m_hdr.mh_flags = 2
        mbuf.M_dat.MH.MH_pkthdr.pkt_hdr = POINTER64(packet_addr)
        mbuf.m_hdr.mh_types = 1
        mbuf.M_dat.MH.MH_dat.MH_ext.ext_buf = POINTER64(0)
        mbuf.updateToMem()

        mbuf_holder = self.ql.os.heap.alloc(8)
        self.ql.mem.write(mbuf_holder, struct.pack("<Q", mbuf_addr))

        packet_header = (ether/ip/last_header).build()

        mbuf2_addr = self.ql.os.heap.alloc(ctypes.sizeof(mbuf_t))
        mbuf2 = mbuf_t(self.ql, mbuf2_addr)
        mbuf2.m_hdr.mh_len = len(data)
        mbuf2.m_hdr.mh_data = POINTER64(packet_addr + len(packet_header))
        mbuf2.m_hdr.mh_flags = 2
        mbuf2.M_dat.MH.MH_pkthdr.pkt_hdr = POINTER64(packet_addr)
        mbuf2.m_hdr.mh_type = 1
        mbuf2.M_dat.MH.MH_dat.MH_ext.ext_buf = POINTER64(packet_addr + len(packet_header))
        mbuf2.updateToMem()

        mbuf2_holder = self.ql.os.heap.alloc(8)
        self.ql.mem.write(mbuf2_holder, struct.pack("<Q", mbuf2_addr))

        # sflt_data_out(void *cookie, socket_t socket, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_DATA_OUT, protocol.value, [cookie, from_idx, self.sockets[to_idx].base, mbuf2_holder, 0, 0])
        # ipf_output(void* cookie, mbuf_t *data, ipf_pktopts_t options)
        self.emit_by_type(MacOSEventType.EV_IPF_OUTPUT, [0, mbuf_holder, 0], ins_cookie=True)

    @init_ev_ctx
    def net_recv(self, cookie, from_idx, to_idx, protocol, last_header, data):
        from scapy.all import Ether, IP, TCP, Raw, ICMP

        ether = Ether(src=self.src_mac, dst=self.dst_mac)
        ip = IP(src=self.src_host, dst=self.dst_host)
        packet_header = (ether).build()
        packet = (ether/ip/last_header/Raw(load=data)).build()

        packet_addr = self.ql.os.heap.alloc(len(packet))
        self.ql.mem.write(packet_addr, packet)

        mbuf_addr = self.ql.os.heap.alloc(ctypes.sizeof(mbuf_t))
        mbuf = mbuf_t(self.ql, mbuf_addr)
        mbuf.m_hdr.mh_len = len(packet) - len(packet_header)
        mbuf.m_hdr.mh_data = POINTER64(packet_addr + len(packet_header))
        mbuf.m_hdr.mh_flags = 2
        mbuf.M_dat.MH.MH_pkthdr.pkt_hdr = POINTER64(packet_addr)
        mbuf.m_hdr.mh_type = 1
        mbuf.M_dat.MH.MH_dat.MH_ext.ext_buf = POINTER64(0)
        mbuf.updateToMem()

        mbuf_holder = self.ql.os.heap.alloc(8)
        self.ql.mem.write(mbuf_holder, struct.pack("<Q", mbuf_addr))

        packet_header = (ether/ip/last_header).build()

        mbuf2_addr = self.ql.os.heap.alloc(ctypes.sizeof(mbuf_t))
        mbuf2 = mbuf_t(self.ql, mbuf2_addr)
        mbuf2.m_hdr.mh_len = len(data)
        mbuf2.m_hdr.mh_data = POINTER64(packet_addr + len(packet_header))
        mbuf2.m_hdr.mh_flags = 2
        mbuf2.M_dat.MH.MH_pkthdr.pkt_hdr = POINTER64(packet_addr)
        mbuf2.m_hdr.mh_type = 1
        mbuf2.M_dat.MH.MH_dat.MH_ext.ext_buf = POINTER64(packet_addr + len(packet_header))
        mbuf2.updateToMem()

        mbuf2_holder = self.ql.os.heap.alloc(8)
        self.ql.mem.write(mbuf2_holder, struct.pack("<Q", mbuf2_addr))

        # sflt_data_in(void *cookie, socket_t socket, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
        self.emit_by_type_and_proto(MacOSEventType.EV_SFLT_DATA_IN, protocol.value, [cookie, from_idx, self.sockets[to_idx].base, mbuf2_holder, 0, 0])
        # ipf_input(void* cookie, mbuf_t *data, int offset, u_int8_t protocol)
        self.emit_by_type(MacOSEventType.EV_IPF_INPUT, [0, mbuf_holder, 0, protocol.value], ins_cookie=True)

    @init_ev_ctx
    def kauth_generic(self, action):
        self.emit("KAUTH_GENERIC", EV_KAUTH_GENERIC, [self.cred.base, 0, action.value, 0, 0, 0, 0])

    @init_ev_ctx
    def kauth_process(self, action):
        signal_addr = self.ql.os.heap.alloc(ctypes.sizeof(c_int))
        self.emit("KAUTH_PROCESS", EV_KAUTH_PROCESS, [self.cred.base, 0, action.value, 0, signal_addr, 0, 0])
        return struct.unpack("<I", signal_addr)

    @init_ev_ctx
    def kauth_vnode(self, action, parent_dir):
        tmp_addr = self.ql.os.heap.alloc(ctypes.sizeof(vnode_t))
        parent_vnode = vnode_t(self.ql, tmp_addr)
        tmp_name = self.ql.os.heap.alloc(len(parent_dir))
        self.ql.mem.write(tmp_name, parent_dir.encode())
        parent_vnode.v_name = POINTER64(tmp_name)
        parent_vnode.updateToMem()

        self.emit("KAUTH_VNODE", EV_KAUTH_VNODE, [self.cred.base, 0, action.value, 0, self.vnode.base, tmp_addr])

# arguments passed to KAUTH_FILEOP_OPEN listeners
#           arg0 is pointer to vnode (vnode *) for given user path.
# 	    arg1 is pointer to path (char *) passed in to open.
# arguments passed to KAUTH_FILEOP_CLOSE listeners
#           arg0 is pointer to vnode (vnode *) for file to be closed.
# 	    arg1 is pointer to path (char *) of file to be closed.
# 	    arg2 is close flags.
# arguments passed to KAUTH_FILEOP_WILL_RENAME listeners
# 	    arg0 is pointer to vnode (vnode *) of the file being renamed
# 	    arg1 is pointer to the "from" path (char *)
# 	    arg2 is pointer to the "to" path (char *)
# arguments passed to KAUTH_FILEOP_RENAME listeners
# 	    arg0 is pointer to "from" path (char *).
# 	    arg1 is pointer to "to" path (char *).
# arguments passed to KAUTH_FILEOP_EXCHANGE listeners
# 	    arg0 is pointer to file 1 path (char *).
# 	    arg1 is pointer to file 2 path (char *).
# arguments passed to KAUTH_FILEOP_LINK listeners
# 	    arg0 is pointer to path to file we are linking to (char *).
# 	    arg1 is pointer to path to the new link file (char *).
# arguments passed to KAUTH_FILEOP_EXEC listeners
# 	    arg0 is pointer to vnode (vnode *) for executable.
# 	    arg1 is pointer to path (char *) to executable.
# arguments passed to KAUTH_FILEOP_DELETE listeners
# 	    arg0 is pointer to vnode (vnode *) of file/dir that was deleted.
# 	    arg1 is pointer to path (char *) of file/dir that was deleted.
    @init_ev_ctx
    def kauth_fileop(self, action, params={}):
        path = self.ql.os.heap.alloc(len(self.current_proc) + 1)
        self.ql.mem.write(path, self.current_proc.encode() + b"\x00")
        if action == Kauth.KAUTH_FILEOP_OPEN:
            self.emit("KAUTH_FILEOP", MacOSEventType.EV_KAUTH_FILEOP, [self.cred.base, 0, action.value, self.vnode.base, path, 0, 0])
        elif action == Kauth.KAUTH_FILEOP_CLOSE:
            self.emit("KAUTH_FILEOP", MacOSEventType.EV_KAUTH_FILEOP, [self.cred.base, 0, action.value, self.vnode.base, path, params["flag"], 0])
        elif action == Kauth.KAUTH_FILEOP_WILL_RENAME:
            new_path = self.ql.os.heap.alloc(len(params["new_path"]) + 1)
            self.ql.mem.write(new_path, params["new_path"] + b"\x00")
            self.emit("KAUTH_FILEOP", MacOSEventType.EV_KAUTH_FILEOP, [self.cred.base, 0, action.value, self.vnode.base, path, new_path, 0])
        elif action == Kauth.KAUTH_FILEOP_RENAME:
            new_path = self.ql.os.heap.alloc(len(params["new_path"]) + 1)
            self.ql.mem.write(new_path, params["new_path"] + b"\x00")
            self.emit("KAUTH_FILEOP", MacOSEventType.EV_KAUTH_FILEOP, [self.cred.base, 0, action.value, path, new_path, 0, 0])
        elif action == Kauth.KAUTH_FILEOP_EXCHANGE:
            file1 = self.ql.os.heap.alloc(len(params["file_1"]) + 1)
            self.ql.mem.write(file1, params["file_1"] + b"\x00")
            file2 = self.ql.os.heap.alloc(len(params["file_2"]) + 1)
            self.ql.mem.write(file2, params["file_2"] + b"\x00")
            self.emit("KAUTH_FILEOP", MacOSEventType.EV_KAUTH_FILEOP, [self.cred.base, 0, action.value, file1, file2, 0, 0])
        elif action == Kauth.KAUTH_FILEOP_LINK:
            file1 = self.ql.os.heap.alloc(len(params["from"]) + 1)
            self.ql.mem.write(file1, params["from"] + b"\x00")
            file2 = self.ql.os.heap.alloc(len(params["to"]) + 1)
            self.ql.mem.write(file2, params["to"] + b"\x00")
            self.emit("KAUTH_FILEOP", MacOSEventType.EV_KAUTH_FILEOP, [self.cred.base, 0, action.value, file1, file2, 0, 0])
        elif action == Kauth.KAUTH_FILEOP_EXEC:
            self.emit("KAUTH_FILEOP", MacOSEventType.EV_KAUTH_FILEOP, [self.cred.base, 0, action.value, self.vnode.base, path, 0, 0])
        elif action == Kauth.KAUTH_FILEOP_DELETE:
            self.emit("KAUTH_FILEOP", MacOSEventType.EV_KAUTH_FILEOP, [self.cred.base, 0, action.value, self.vnode.base, path, 0, 0])

    # /bsd/kern/syscalls.master
    def syscall(self, sysnum, params):
        nsyscall, = struct.unpack("<Q", self.ql.mem.read(self.ql.loader.kernel_extrn_symbols_detail[b"_nsysent"]["n_value"], 8))
        sysent = self.ql.loader.kernel_local_symbols_detail[b"_sysent"]["n_value"]
        system_table = [sysent_t(self.ql, sysent + x * ctypes.sizeof(sysent_t)).loadFromMem() for x in range(nsyscall)]

        self.ql.reg.write(UC_X86_REG_RAX, sysnum)
        reg_list = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9]
        for idx, p in enumerate(params):
            self.ql.reg.write(reg_list[idx], p)
        self.ql.os.savedrip=self.deadcode
        self.ql.run(begin=system_table[sysnum].sy_call.value)
