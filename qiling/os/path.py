#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Optional, Union
from pathlib import Path, PurePosixPath, PureWindowsPath

from qiling.const import QL_OS, QL_OS_POSIX

AnyPurePath = Union[PurePosixPath, PureWindowsPath]

class QlOsPath:
    """Virtual to host path manipulations helper.
    """

    def __init__(self, rootfs: str, cwd: str, emulos: QL_OS) -> None:
        """Initialize a path manipulation object.

        Args:
            rootfs : host path to serve as the virtual root directory
            cwd    : virtual current working directory
            emuls  : emulated operating system
        """

        nt_path_os = (QL_OS.WINDOWS, QL_OS.DOS)
        posix_path_os = QL_OS_POSIX

        # rootfs is a local directory on the host, and expected to exist
        self._rootfs_path = Path(rootfs).resolve(strict=True)

        # determine how virtual paths should be handled
        if emulos in nt_path_os:
            self.PureVirtualPath = PureWindowsPath

        elif emulos in posix_path_os:
            self.PureVirtualPath = PurePosixPath

        else:
            raise ValueError(f'unexpected os type: {emulos}')

        self.cwd = cwd

        # <TEMPORARY>
        self.transform_to_relative_path = self.virtual_abspath
        self.transform_to_real_path = self.virtual_to_host_path
        self.transform_to_link_path = self.virtual_to_host_path
        # </TEMPORARY>

    @staticmethod
    def __strip_parent_refs(path: AnyPurePath) -> AnyPurePath:
        """Strip leading parent dir references, if any.
        """

        if path.parts:
            pardir = r'..'

            while path.parts[0] == pardir:
                path = path.relative_to(pardir)

        return path

    @property
    def cwd(self) -> str:
        return str(self._cwd_anchor / self._cwd_vpath)

    @cwd.setter
    def cwd(self, virtpath: str) -> None:
        vpath = self.PureVirtualPath(virtpath)

        if not vpath.is_absolute():
            raise ValueError(f'current working directory must be an absolute path: {virtpath}')

        # extract the virtual path anchor so we can append cwd path to rootfs later on.
        # however, we will still need the anchor to provide full virtual paths
        cwd_anchor = self.PureVirtualPath(vpath.anchor)
        cwd_vpath = vpath.relative_to(cwd_anchor)

        cwd_vpath = QlOsPath.__strip_parent_refs(cwd_vpath)

        self._cwd_anchor = cwd_anchor
        self._cwd_vpath = cwd_vpath

    def __virtual_abspath(self, virtpath: Union[str, AnyPurePath]) -> AnyPurePath:
        """Get the absolute virtual path representation of a virtual path.
        This method does not follow symbolic links or parent directory references.

        Args:
            virtpath: virtual path to resolve, either relative or absolute

        Returns: An absolute virtual path
        """

        vpath = self.PureVirtualPath(virtpath)

        if vpath.is_absolute():
            return vpath

        # rebase on top the current working directory. in case vpath is an absolute
        # path, cwd will be discarded
        absvpath = self._cwd_vpath / vpath

        # referencing root's parent directory should circle back to root.
        # remove any leading parent dir references absvpath might have
        absvpath = QlOsPath.__strip_parent_refs(absvpath)

        return self._cwd_anchor / absvpath

    def __resolved_vsymlink(self, basepath: Path, name: str):
        """Attempt to resolve a virtual symbolic link.

        A virtual symbolic link points to a location within the virtual file
        system, not to be confused with paths on the host file system.

        For example:
            a vsymlink that points to '/var/tmp' should be resolved to
            'my/rootfs/path/var/tmp' on the host
        """

        fullpath = self._rootfs_path / basepath / name
        vpath = None

        if fullpath.is_symlink():
            resolved = fullpath.resolve(strict=False)

            try:
                # the resolve method turns fullpath into an absolute path on the host,
                # but we need it to be an absolute virtual path. to convert the host
                # path to virtual we have to make sure it resides within rootfs.
                #
                # if the host path is indeed under rootfs, we can rebase the virtual
                # portion on top of rootfs and return an absolute virtual path.
                #
                # returning an absolute path will discard the accumulated vpath.

                vpath = self._cwd_anchor / resolved.relative_to(self._rootfs_path)
            except ValueError:
                # failing to convert the host path into a virtual one means that either
                # the symbolic link is already an absolute virtual path, or it is pointing
                # to an external directory on the host file system, which means it does
                # not reflect a virtual path.
                #
                # on both cases we may return the path as-is, discarding the accumulated
                # vpath.
                #
                # that, however, may not work in case the host filesystem and the virtual
                # one are not of the same type (e.g. a virtual Windows path on top of a
                # Linux host): the absolute path will not discard the accumulated vpath
                # and will be appended - which is a corner case we do not know how to
                # handle efficiently.

                vpath = resolved

        return vpath

    # this will work only if hosting os = virtual os
    def __virtual_resolve(self, virtpath: Union[str, AnyPurePath]) -> AnyPurePath:
        """Resolve a virtual path, including symbolic links and directory
        references it might include. Path must not include circular symbolic
        links.

        Args:
            virtpath: virtual path to resolve, either relative or absolute

        Returns: An absolute virtual path
        """

        vpath = self.PureVirtualPath(virtpath)

        # if not already, turn vpath into an absolute path
        if not vpath.is_absolute():
            vpath = self.__virtual_abspath(vpath)

        # accumulate paths as we progress through the resolution process.
        #
        # since symlink inspection and resolution can only be done on an
        # actual file system, each step in the progress has to be translated
        # into its correpsonding host path. that is the reason we keep track
        # on the acumulated host path in parallel to the virtual one
        #
        # note: the reason we do not set acc_hpath to rootfs is to prevent
        # parent dir refs from traversing beyond rootfs directory.

        acc_hpath = Path()
        acc_vpath = self.PureVirtualPath(vpath.anchor)

        # eliminate virtual path's anchor to allow us accumulate its
        # parts on top of rootfs
        vpath = vpath.relative_to(vpath.anchor)

        for part in vpath.parts:
            if part == '..':
                acc_hpath = acc_hpath.parent
                acc_vpath = acc_vpath.parent

            else:
                # if this is a symlink attempt to resolve it
                vtemp = self.__resolved_vsymlink(acc_hpath, part)

                # not a symlink; accumulate path part
                if vtemp is None:
                    acc_hpath = acc_hpath / part
                    acc_vpath = acc_vpath / part

                else:
                    # rebase it on top of the accumulated virtual path
                    new_vpath = acc_vpath / vtemp

                    # recursively resolve the new virtual path we got
                    vres = self.__virtual_resolve(new_vpath)

                    acc_hpath = Path(vres)
                    acc_vpath = vres

        return acc_vpath

    def __virtual_to_host_path(self, virtpath: Union[str, AnyPurePath]) -> Path:
        """Convert a virtual path to its corresponding path on the host.

        This method partialy normalizes the virtual path and does not resolve
        references to parent directories neither virtual symbolic links
        """

        absvpath = self.__virtual_abspath(virtpath)

        # remove path anchor to allow path to be rebased
        vpath = absvpath.relative_to(absvpath.anchor)

        # rebase virtual path on top of rootfs to get the host path
        return self._rootfs_path / vpath

    def __is_safe_host_path(self, hostpath: Path, strict: bool = False) -> bool:
        """Sanitize the specified host path and make sure it does not traverse out
        of the rootfs directory hierarchy.

        Args:
            hostpath : a local path to sanitize
            strict   : whether to raise an error if target path does not exist

        Returns: whether the path is safe to use
        """

        # canonicalization before assertion: resolve any relative path references and
        # symbolic links that may exist.
        #
        # in case strict is set to True and the path does not exist, a FileNotFoundError
        # is raised. this error is left for the user to catch and handle
        hostpath = hostpath.resolve(strict=strict)

        try:
            # to prevent path-traversal issues we have to make sure hostpath ended up
            # as a subpath of rootfs. the following method will fail if that is not
            # the case
            _ = hostpath.relative_to(self._rootfs_path)
        except ValueError:
            return False

        else:
            return True

    def virtual_abspath(self, virtpath: str) -> str:
        """Convert a relative virtual path to an absolute virtual path based
        on the current working directory.

        Args:
            virtpath : relative virtual path

        Returns: the absolute virtual path
        """

        absvpath = self.__virtual_abspath(virtpath)

        return str(absvpath)

    def virtual_to_host_path(self, virtpath: str) -> str:
        """Convert a virtual path to its corresponding path on the hosting system.

        Args:
            virtpath : path on the emulated system. the path may be either absolute
            or relative

        Returns: the corresponding path on the hosting system
        """

        absvpath = self.__virtual_resolve(virtpath)
        hostpath = self.__virtual_to_host_path(absvpath)

        return str(hostpath)

    def is_safe_host_path(self, hostpath: str) -> bool:
        hpath = Path(hostpath)

        return self.__is_safe_host_path(hpath, strict=False)

    @staticmethod
    def __host_casefold_path(hostpath: str) -> Optional[str]:
        # assuming posix host
        p = PurePosixPath(hostpath)
        norm = Path(p.anchor)

        for elem in p.relative_to(norm).parts:
            folded = elem.casefold()

            try:
                norm = next(entry for entry in norm.iterdir() if entry.name.casefold() == folded)
            except StopIteration:
                return None

        return str(norm)

    def host_casefold_path(self, hostpath: str) -> Optional[str]:
        """As opposed to POSIX paths, NT paths are case insensitive and may be specified
        in multiple ways. When emulating an NT file system on top of POSIX one, virtual
        NT paths and files might not be found because they are specified in a different
        case than the one that is actually used on the hosting POSIX system.

        This method translates a case insensitive path into the actual case sensitive
        name that is used on the hosting POSIX file system.

        Args:
            hostpath: a path on the host, case insensitive

        Returns: the corresponding path on the host system, or None if the path does not
        exist
        """

        # only relevant if the emulated file system is NT-based
        if self.PureVirtualPath is PureWindowsPath:
            return QlOsPath.__host_casefold_path(hostpath)

        return hostpath

