#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes, enum

from functools import wraps

from .macos_structs import label_t, ucred_t, POINTER64, fileglob_t, vnode_t


def init_ctx(f):
    @wraps(f)
    def wrapper(self, *args, **kw):
        if self.manager.label is None:
            label_addr = self.ql.os.heap.alloc(ctypes.sizeof(label_t))
            self.manager.label = label_t(self.ql, label_addr)
            self.manager.label.l_flags = 1
            self.manager.label.updateToMem()

        if self.manager.cred is None:
            cred_addr = self.ql.os.heap.alloc(ctypes.sizeof(ucred_t))
            self.manager.cred = ucred_t(self.ql, cred_addr)
            self.manager.cred.cr_ref = 2
            pyarr = [
                20,
                12,
                61,
                79,
                80,
                81,
                98,
                33,
                100,
                204,
                250,
                395,
                398,
                399,
                701,
                0,
            ]
            self.manager.cred.cr_posix = ucred_t.posix_cred_t(
                501,
                501,
                501,
                15,
                (ctypes.c_uint32 * len(pyarr))(*pyarr),
                20,
                20,
                501,
                2,
            )
            self.manager.cred.cr_label = POINTER64(self.manager.label.base)
            self.manager.cred.updateToMem()

        if self.manager.vnode is None:
            tmp_addr = self.ql.os.heap.alloc(ctypes.sizeof(vnode_t))
            self.manager.vnode = vnode_t(self.ql, tmp_addr)
            tmp_name = self.ql.os.heap.alloc(len(self.manager.current_proc))
            self.manager.ql.mem.write(
                tmp_name, self.manager.current_proc.encode()
            )
            self.manager.vnode.v_name = POINTER64(tmp_name)
            self.manager.vnode.updateToMem()

        return f(self, *args, **kw)

    return wrapper


class QlMacOSPolicy:
    def __init__(self, ql, manager):
        self.ql = ql
        self.manager = manager
        self.bank = {}

    @init_ctx
    def mpo_file_check_mmap(self, prot, flags, file_pos):
        if self.manager.vnode is None or self.manager.cred is None:
            ql.log.info("Invalid vnode or credential")
            return
        fg_addr = self.ql.os.heap.alloc(ctypes.sizeof(fileglob_t))
        fg = fileglob_t(self.ql, fg_addr)
        fg.fg_flag = 1
        fg.fg_count = 1
        fg.fg_cred = POINTER64(self.manager.cred.base)
        fg.fg_data = POINTER64(self.manager.vnode.base)
        fg.updateToMem()

        self.manager.emit_by_type(
            MACPolicy_EventType.EV_MAC_mpo_file_check_mmap,
            [
                self.manager.cred.base,
                fg_addr,
                self.manager.label.base,
                prot,
                flags,
                file_pos,
                0,
            ],
        )


base_event_MAC = 0x2000


class AutoNumber(enum.Enum):
    def __new__(cls):
        value = len(cls.__members__) + base_event_MAC
        obj = object.__new__(cls)
        obj._value_ = value
        return obj


NUM_EVENT_MAC_POLICY = 335


class MACPolicy_EventType(AutoNumber):
    EV_MAC_mpo_audit_check_postselect = ()
    EV_MAC_mpo_audit_check_preselect = ()
    EV_MAC_mpo_bpfdesc_label_associate = ()
    EV_MAC_mpo_bpfdesc_label_destroy = ()
    EV_MAC_mpo_bpfdesc_label_init = ()
    EV_MAC_mpo_bpfdesc_check_receive = ()
    EV_MAC_mpo_cred_check_label_update_execve = ()
    EV_MAC_mpo_cred_check_label_update = ()
    EV_MAC_mpo_cred_check_visible = ()
    EV_MAC_mpo_cred_label_associate_fork = ()
    EV_MAC_mpo_cred_label_associate_kernel = ()
    EV_MAC_mpo_cred_label_associate = ()
    EV_MAC_mpo_cred_label_associate_user = ()
    EV_MAC_mpo_cred_label_destroy = ()
    EV_MAC_mpo_cred_label_externalize_audit = ()
    EV_MAC_mpo_cred_label_externalize = ()
    EV_MAC_mpo_cred_label_init = ()
    EV_MAC_mpo_cred_label_internalize = ()
    EV_MAC_mpo_cred_label_update_execve = ()
    EV_MAC_mpo_cred_label_update = ()
    EV_MAC_mpo_devfs_label_associate_device = ()
    EV_MAC_mpo_devfs_label_associate_directory = ()
    EV_MAC_mpo_devfs_label_copy = ()
    EV_MAC_mpo_devfs_label_destroy = ()
    EV_MAC_mpo_devfs_label_init = ()
    EV_MAC_mpo_devfs_label_update = ()
    EV_MAC_mpo_file_check_change_offset = ()
    EV_MAC_mpo_file_check_create = ()
    EV_MAC_mpo_file_check_dup = ()
    EV_MAC_mpo_file_check_fcntl = ()
    EV_MAC_mpo_file_check_get_offset = ()
    EV_MAC_mpo_file_check_get = ()
    EV_MAC_mpo_file_check_inherit = ()
    EV_MAC_mpo_file_check_ioctl = ()
    EV_MAC_mpo_file_check_lock = ()
    EV_MAC_mpo_file_check_mmap_downgrade = ()
    EV_MAC_mpo_file_check_mmap = ()
    EV_MAC_mpo_file_check_receive = ()
    EV_MAC_mpo_file_check_set = ()
    EV_MAC_mpo_file_label_init = ()
    EV_MAC_mpo_file_label_destroy = ()
    EV_MAC_mpo_file_label_associate = ()
    EV_MAC_mpo_ifnet_check_label_update = ()
    EV_MAC_mpo_ifnet_check_transmit = ()
    EV_MAC_mpo_ifnet_label_associate = ()
    EV_MAC_mpo_ifnet_label_copy = ()
    EV_MAC_mpo_ifnet_label_destroy = ()
    EV_MAC_mpo_ifnet_label_externalize = ()
    EV_MAC_mpo_ifnet_label_init = ()
    EV_MAC_mpo_ifnet_label_internalize = ()
    EV_MAC_mpo_ifnet_label_update = ()
    EV_MAC_mpo_ifnet_label_recycle = ()
    EV_MAC_mpo_inpcb_check_deliver = ()
    EV_MAC_mpo_inpcb_label_associate = ()
    EV_MAC_mpo_inpcb_label_destroy = ()
    EV_MAC_mpo_inpcb_label_init = ()
    EV_MAC_mpo_inpcb_label_recycle = ()
    EV_MAC_mpo_inpcb_label_update = ()
    EV_MAC_mpo_iokit_check_device = ()
    EV_MAC_mpo_ipq_label_associate = ()
    EV_MAC_mpo_ipq_label_compare = ()
    EV_MAC_mpo_ipq_label_destroy = ()
    EV_MAC_mpo_ipq_label_init = ()
    EV_MAC_mpo_ipq_label_update = ()
    EV_MAC_mpo_file_check_library_validation = ()
    EV_MAC_mpo_vnode_notify_setacl = ()
    EV_MAC_mpo_vnode_notify_setattrlist = ()
    EV_MAC_mpo_vnode_notify_setextattr = ()
    EV_MAC_mpo_vnode_notify_setflags = ()
    EV_MAC_mpo_vnode_notify_setmode = ()
    EV_MAC_mpo_vnode_notify_setowner = ()
    EV_MAC_mpo_vnode_notify_setutimes = ()
    EV_MAC_mpo_vnode_notify_truncate = ()
    EV_MAC_mpo_mbuf_label_associate_bpfdesc = ()
    EV_MAC_mpo_mbuf_label_associate_ifnet = ()
    EV_MAC_mpo_mbuf_label_associate_inpcb = ()
    EV_MAC_mpo_mbuf_label_associate_ipq = ()
    EV_MAC_mpo_mbuf_label_associate_linklayer = ()
    EV_MAC_mpo_mbuf_label_associate_multicast_encap = ()
    EV_MAC_mpo_mbuf_label_associate_netlayer = ()
    EV_MAC_mpo_mbuf_label_associate_socket = ()
    EV_MAC_mpo_mbuf_label_copy = ()
    EV_MAC_mpo_mbuf_label_destroy = ()
    EV_MAC_mpo_mbuf_label_init = ()
    EV_MAC_mpo_mount_check_fsctl = ()
    EV_MAC_mpo_mount_check_getattr = ()
    EV_MAC_mpo_mount_check_label_update = ()
    EV_MAC_mpo_mount_check_mount = ()
    EV_MAC_mpo_mount_check_remount = ()
    EV_MAC_mpo_mount_check_setattr = ()
    EV_MAC_mpo_mount_check_stat = ()
    EV_MAC_mpo_mount_check_umount = ()
    EV_MAC_mpo_mount_label_associate = ()
    EV_MAC_mpo_mount_label_destroy = ()
    EV_MAC_mpo_mount_label_externalize = ()
    EV_MAC_mpo_mount_label_init = ()
    EV_MAC_mpo_mount_label_internalize = ()
    EV_MAC_mpo_netinet_fragment = ()
    EV_MAC_mpo_netinet_icmp_reply = ()
    EV_MAC_mpo_netinet_tcp_reply = ()
    EV_MAC_mpo_pipe_check_ioctl = ()
    EV_MAC_mpo_pipe_check_kqfilter = ()
    EV_MAC_mpo_pipe_check_label_update = ()
    EV_MAC_mpo_pipe_check_read = ()
    EV_MAC_mpo_pipe_check_select = ()
    EV_MAC_mpo_pipe_check_stat = ()
    EV_MAC_mpo_pipe_check_write = ()
    EV_MAC_mpo_pipe_label_associate = ()
    EV_MAC_mpo_pipe_label_copy = ()
    EV_MAC_mpo_pipe_label_destroy = ()
    EV_MAC_mpo_pipe_label_externalize = ()
    EV_MAC_mpo_pipe_label_init = ()
    EV_MAC_mpo_pipe_label_internalize = ()
    EV_MAC_mpo_pipe_label_update = ()
    EV_MAC_mpo_policy_destroy = ()
    EV_MAC_mpo_policy_init = ()
    EV_MAC_mpo_policy_initbsd = ()
    EV_MAC_mpo_policy_syscall = ()
    EV_MAC_mpo_system_check_sysctlbyname = ()
    EV_MAC_mpo_proc_check_inherit_ipc_ports = ()
    EV_MAC_mpo_vnode_check_rename = ()
    EV_MAC_mpo_kext_check_query = ()
    EV_MAC_mpo_proc_notify_exec_complete = ()
    EV_MAC_mpo_reserved5 = ()
    EV_MAC_mpo_reserved6 = ()
    EV_MAC_mpo_proc_check_expose_task = ()
    EV_MAC_mpo_proc_check_set_host_special_port = ()
    EV_MAC_mpo_proc_check_set_host_exception_port = ()
    EV_MAC_mpo_exc_action_check_exception_send = ()
    EV_MAC_mpo_exc_action_label_associate = ()
    EV_MAC_mpo_exc_action_label_populate = ()
    EV_MAC_mpo_exc_action_label_destroy = ()
    EV_MAC_mpo_exc_action_label_init = ()
    EV_MAC_mpo_exc_action_label_update = ()
    EV_MAC_mpo_vnode_check_trigger_resolve = ()
    EV_MAC_mpo_reserved1 = ()
    EV_MAC_mpo_reserved2 = ()
    EV_MAC_mpo_reserved3 = ()
    EV_MAC_mpo_skywalk_flow_check_connect = ()
    EV_MAC_mpo_skywalk_flow_check_listen = ()
    EV_MAC_mpo_posixsem_check_create = ()
    EV_MAC_mpo_posixsem_check_open = ()
    EV_MAC_mpo_posixsem_check_post = ()
    EV_MAC_mpo_posixsem_check_unlink = ()
    EV_MAC_mpo_posixsem_check_wait = ()
    EV_MAC_mpo_posixsem_label_associate = ()
    EV_MAC_mpo_posixsem_label_destroy = ()
    EV_MAC_mpo_posixsem_label_init = ()
    EV_MAC_mpo_posixshm_check_create = ()
    EV_MAC_mpo_posixshm_check_mmap = ()
    EV_MAC_mpo_posixshm_check_open = ()
    EV_MAC_mpo_posixshm_check_stat = ()
    EV_MAC_mpo_posixshm_check_truncate = ()
    EV_MAC_mpo_posixshm_check_unlink = ()
    EV_MAC_mpo_posixshm_label_associate = ()
    EV_MAC_mpo_posixshm_label_destroy = ()
    EV_MAC_mpo_posixshm_label_init = ()
    EV_MAC_mpo_proc_check_debug = ()
    EV_MAC_mpo_proc_check_fork = ()
    EV_MAC_mpo_proc_check_get_task_name = ()
    EV_MAC_mpo_proc_check_get_task = ()
    EV_MAC_mpo_proc_check_getaudit = ()
    EV_MAC_mpo_proc_check_getauid = ()
    EV_MAC_mpo_proc_check_getlcid = ()
    EV_MAC_mpo_proc_check_mprotect = ()
    EV_MAC_mpo_proc_check_sched = ()
    EV_MAC_mpo_proc_check_setaudit = ()
    EV_MAC_mpo_proc_check_setauid = ()
    EV_MAC_mpo_proc_check_setlcid = ()
    EV_MAC_mpo_proc_check_signal = ()
    EV_MAC_mpo_proc_check_wait = ()
    EV_MAC_mpo_proc_label_destroy = ()
    EV_MAC_mpo_proc_label_init = ()
    EV_MAC_mpo_socket_check_accept = ()
    EV_MAC_mpo_socket_check_accepted = ()
    EV_MAC_mpo_socket_check_bind = ()
    EV_MAC_mpo_socket_check_connect = ()
    EV_MAC_mpo_socket_check_create = ()
    EV_MAC_mpo_socket_check_deliver = ()
    EV_MAC_mpo_socket_check_kqfilter = ()
    EV_MAC_mpo_socket_check_label_update = ()
    EV_MAC_mpo_socket_check_listen = ()
    EV_MAC_mpo_socket_check_receive = ()
    EV_MAC_mpo_socket_check_received = ()
    EV_MAC_mpo_socket_check_select = ()
    EV_MAC_mpo_socket_check_send = ()
    EV_MAC_mpo_socket_check_stat = ()
    EV_MAC_mpo_socket_check_setsockopt = ()
    EV_MAC_mpo_socket_check_getsockopt = ()
    EV_MAC_mpo_socket_label_associate_accept = ()
    EV_MAC_mpo_socket_label_associate = ()
    EV_MAC_mpo_socket_label_copy = ()
    EV_MAC_mpo_socket_label_destroy = ()
    EV_MAC_mpo_socket_label_externalize = ()
    EV_MAC_mpo_socket_label_init = ()
    EV_MAC_mpo_socket_label_internalize = ()
    EV_MAC_mpo_socket_label_update = ()
    EV_MAC_mpo_socketpeer_label_associate_mbuf = ()
    EV_MAC_mpo_socketpeer_label_associate_socket = ()
    EV_MAC_mpo_socketpeer_label_destroy = ()
    EV_MAC_mpo_socketpeer_label_externalize = ()
    EV_MAC_mpo_socketpeer_label_init = ()
    EV_MAC_mpo_system_check_acct = ()
    EV_MAC_mpo_system_check_audit = ()
    EV_MAC_mpo_system_check_auditctl = ()
    EV_MAC_mpo_system_check_auditon = ()
    EV_MAC_mpo_system_check_host_priv = ()
    EV_MAC_mpo_system_check_nfsd = ()
    EV_MAC_mpo_system_check_reboot = ()
    EV_MAC_mpo_system_check_settime = ()
    EV_MAC_mpo_system_check_swapoff = ()
    EV_MAC_mpo_system_check_swapon = ()
    EV_MAC_mpo_socket_check_ioctl = ()
    EV_MAC_mpo_sysvmsg_label_associate = ()
    EV_MAC_mpo_sysvmsg_label_destroy = ()
    EV_MAC_mpo_sysvmsg_label_init = ()
    EV_MAC_mpo_sysvmsg_label_recycle = ()
    EV_MAC_mpo_sysvmsq_check_enqueue = ()
    EV_MAC_mpo_sysvmsq_check_msgrcv = ()
    EV_MAC_mpo_sysvmsq_check_msgrmid = ()
    EV_MAC_mpo_sysvmsq_check_msqctl = ()
    EV_MAC_mpo_sysvmsq_check_msqget = ()
    EV_MAC_mpo_sysvmsq_check_msqrcv = ()
    EV_MAC_mpo_sysvmsq_check_msqsnd = ()
    EV_MAC_mpo_sysvmsq_label_associate = ()
    EV_MAC_mpo_sysvmsq_label_destroy = ()
    EV_MAC_mpo_sysvmsq_label_init = ()
    EV_MAC_mpo_sysvmsq_label_recycle = ()
    EV_MAC_mpo_sysvsem_check_semctl = ()
    EV_MAC_mpo_sysvsem_check_semget = ()
    EV_MAC_mpo_sysvsem_check_semop = ()
    EV_MAC_mpo_sysvsem_label_associate = ()
    EV_MAC_mpo_sysvsem_label_destroy = ()
    EV_MAC_mpo_sysvsem_label_init = ()
    EV_MAC_mpo_sysvsem_label_recycle = ()
    EV_MAC_mpo_sysvshm_check_shmat = ()
    EV_MAC_mpo_sysvshm_check_shmctl = ()
    EV_MAC_mpo_sysvshm_check_shmdt = ()
    EV_MAC_mpo_sysvshm_check_shmget = ()
    EV_MAC_mpo_sysvshm_label_associate = ()
    EV_MAC_mpo_sysvshm_label_destroy = ()
    EV_MAC_mpo_sysvshm_label_init = ()
    EV_MAC_mpo_sysvshm_label_recycle = ()
    EV_MAC_mpo_proc_notify_exit = ()
    EV_MAC_mpo_mount_check_snapshot_revert = ()
    EV_MAC_mpo_vnode_check_getattr = ()
    EV_MAC_mpo_mount_check_snapshot_create = ()
    EV_MAC_mpo_mount_check_snapshot_delete = ()
    EV_MAC_mpo_vnode_check_clone = ()
    EV_MAC_mpo_proc_check_get_cs_info = ()
    EV_MAC_mpo_proc_check_set_cs_info = ()
    EV_MAC_mpo_iokit_check_hid_control = ()
    EV_MAC_mpo_vnode_check_access = ()
    EV_MAC_mpo_vnode_check_chdir = ()
    EV_MAC_mpo_vnode_check_chroot = ()
    EV_MAC_mpo_vnode_check_create = ()
    EV_MAC_mpo_vnode_check_deleteextattr = ()
    EV_MAC_mpo_vnode_check_exchangedata = ()
    EV_MAC_mpo_vnode_check_exec = ()
    EV_MAC_mpo_vnode_check_getattrlist = ()
    EV_MAC_mpo_vnode_check_getextattr = ()
    EV_MAC_mpo_vnode_check_ioctl = ()
    EV_MAC_mpo_vnode_check_kqfilter = ()
    EV_MAC_mpo_vnode_check_label_update = ()
    EV_MAC_mpo_vnode_check_link = ()
    EV_MAC_mpo_vnode_check_listextattr = ()
    EV_MAC_mpo_vnode_check_lookup = ()
    EV_MAC_mpo_vnode_check_open = ()
    EV_MAC_mpo_vnode_check_read = ()
    EV_MAC_mpo_vnode_check_readdir = ()
    EV_MAC_mpo_vnode_check_readlink = ()
    EV_MAC_mpo_vnode_check_rename_from = ()
    EV_MAC_mpo_vnode_check_rename_to = ()
    EV_MAC_mpo_vnode_check_revoke = ()
    EV_MAC_mpo_vnode_check_select = ()
    EV_MAC_mpo_vnode_check_setattrlist = ()
    EV_MAC_mpo_vnode_check_setextattr = ()
    EV_MAC_mpo_vnode_check_setflags = ()
    EV_MAC_mpo_vnode_check_setmode = ()
    EV_MAC_mpo_vnode_check_setowner = ()
    EV_MAC_mpo_vnode_check_setutimes = ()
    EV_MAC_mpo_vnode_check_stat = ()
    EV_MAC_mpo_vnode_check_truncate = ()
    EV_MAC_mpo_vnode_check_unlink = ()
    EV_MAC_mpo_vnode_check_write = ()
    EV_MAC_mpo_vnode_label_associate_devfs = ()
    EV_MAC_mpo_vnode_label_associate_extattr = ()
    EV_MAC_mpo_vnode_label_associate_file = ()
    EV_MAC_mpo_vnode_label_associate_pipe = ()
    EV_MAC_mpo_vnode_label_associate_posixsem = ()
    EV_MAC_mpo_vnode_label_associate_posixshm = ()
    EV_MAC_mpo_vnode_label_associate_singlelabel = ()
    EV_MAC_mpo_vnode_label_associate_socket = ()
    EV_MAC_mpo_vnode_label_copy = ()
    EV_MAC_mpo_vnode_label_destroy = ()
    EV_MAC_mpo_vnode_label_externalize_audit = ()
    EV_MAC_mpo_vnode_label_externalize = ()
    EV_MAC_mpo_vnode_label_init = ()
    EV_MAC_mpo_vnode_label_internalize = ()
    EV_MAC_mpo_vnode_label_recycle = ()
    EV_MAC_mpo_vnode_label_store = ()
    EV_MAC_mpo_vnode_label_update_extattr = ()
    EV_MAC_mpo_vnode_label_update = ()
    EV_MAC_mpo_vnode_notify_create = ()
    EV_MAC_mpo_vnode_check_signature = ()
    EV_MAC_mpo_vnode_check_uipc_bind = ()
    EV_MAC_mpo_vnode_check_uipc_connect = ()
    EV_MAC_mpo_proc_check_run_cs_invalid = ()
    EV_MAC_mpo_proc_check_suspend_resume = ()
    EV_MAC_mpo_thread_userret = ()
    EV_MAC_mpo_iokit_check_set_properties = ()
    EV_MAC_mpo_system_check_chud = ()
    EV_MAC_mpo_vnode_check_searchfs = ()
    EV_MAC_mpo_priv_check = ()
    EV_MAC_mpo_priv_grant = ()
    EV_MAC_mpo_proc_check_map_anon = ()
    EV_MAC_mpo_vnode_check_fsgetpath = ()
    EV_MAC_mpo_iokit_check_open = ()
    EV_MAC_mpo_proc_check_ledger = ()
    EV_MAC_mpo_vnode_notify_rename = ()
    EV_MAC_mpo_vnode_check_setacl = ()
    EV_MAC_mpo_vnode_notify_deleteextattr = ()
    EV_MAC_mpo_system_check_kas_info = ()
    EV_MAC_mpo_vnode_check_lookup_preflight = ()
    EV_MAC_mpo_vnode_notify_open = ()
    EV_MAC_mpo_system_check_info = ()
    EV_MAC_mpo_pty_notify_grant = ()
    EV_MAC_mpo_pty_notify_close = ()
    EV_MAC_mpo_vnode_find_sigs = ()
    EV_MAC_mpo_kext_check_load = ()
    EV_MAC_mpo_kext_check_unload = ()
    EV_MAC_mpo_proc_check_proc_info = ()
    EV_MAC_mpo_vnode_notify_link = ()
    EV_MAC_mpo_iokit_check_filter_properties = ()
    EV_MAC_mpo_iokit_check_get_property = ()
