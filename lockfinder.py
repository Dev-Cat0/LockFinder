"""
LockFinder - "다른 프로그램에서 사용 중" 범인 찾기 도구 (Windows)

파일/폴더를 고르면 어떤 프로세스가 붙잡고 있는지 보여주고,
선택해서 종료하거나 바로 삭제까지 할 수 있습니다.

- 파일 잠금 탐지: Windows Restart Manager API (ctypes, 추가 설치 불필요)
- 폴더 작업 디렉터리/실행 경로 탐지 + 프로세스 종료: psutil
"""
import ctypes
import os
import shutil
import sys
import threading
import tkinter as tk
from ctypes import wintypes
from tkinter import filedialog, messagebox, ttk

import psutil

APP_TITLE = "LockFinder - 누가 내 파일을 붙잡고 있나?"
MAX_FILES_SCAN = 5000  # 폴더 검사 시 최대 파일 수
CHUNK = 200            # Restart Manager에 한 번에 등록할 파일 수

# 건드리면 시스템이 망가지는 프로세스는 종료 금지
PROTECTED = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "fontdrvhost.exe", "memory compression",
}

APP_TYPES = {
    0: "알 수 없음", 1: "일반 프로그램", 2: "창이 있는 프로그램", 3: "서비스",
    4: "탐색기", 5: "콘솔", 1000: "중요 시스템",
}


# ---------------------------------------------------------------- Restart Manager
class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD),
                ("ProcessStartTime", wintypes.FILETIME)]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("Process", RM_UNIQUE_PROCESS),
                ("strAppName", ctypes.c_wchar * 256),
                ("strServiceShortName", ctypes.c_wchar * 64),
                ("ApplicationType", ctypes.c_int),
                ("AppStatus", ctypes.c_ulong),
                ("TSSessionId", wintypes.DWORD),
                ("bRestartable", wintypes.BOOL)]


def _rm_lockers(paths):
    """파일 경로 리스트를 붙잡고 있는 프로세스 [(pid, 앱이름, 타입)] 반환."""
    rstrtmgr = ctypes.WinDLL("rstrtmgr")
    ERROR_MORE_DATA = 234
    handle = wintypes.DWORD(0)
    key = ctypes.create_unicode_buffer(33)
    if rstrtmgr.RmStartSession(ctypes.byref(handle), 0, key) != 0:
        return []
    found = []
    try:
        arr_type = ctypes.c_wchar_p * len(paths)
        if rstrtmgr.RmRegisterResources(handle, len(paths), arr_type(*paths),
                                        0, None, 0, None) != 0:
            return []
        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        res = rstrtmgr.RmGetList(handle, ctypes.byref(needed), ctypes.byref(count),
                                 None, ctypes.byref(reasons))
        while res == ERROR_MORE_DATA:
            count = wintypes.UINT(needed.value)
            infos = (RM_PROCESS_INFO * count.value)()
            res = rstrtmgr.RmGetList(handle, ctypes.byref(needed), ctypes.byref(count),
                                     infos, ctypes.byref(reasons))
            if res == 0:
                for i in range(count.value):
                    p = infos[i]
                    found.append((p.Process.dwProcessId, p.strAppName,
                                  APP_TYPES.get(p.ApplicationType, "기타")))
    finally:
        rstrtmgr.RmEndSession(handle)
    return found


def _is_under(path, folder):
    try:
        path = os.path.normcase(os.path.abspath(path))
        folder = os.path.normcase(os.path.abspath(folder))
        return path == folder or path.startswith(folder + os.sep)
    except Exception:
        return False


def find_lockers(target):
    """target(파일/폴더)을 사용 중인 프로세스 dict {pid: info} 반환."""
    result = {}

    def add(pid, reason, app_type="일반 프로그램", app_name=""):
        if pid == os.getpid() or pid == 0:
            return
        info = result.get(pid)
        if info is None:
            try:
                p = psutil.Process(pid)
                name, exe = p.name(), ""
                try:
                    exe = p.exe()
                except Exception:
                    pass
            except psutil.Error:
                name, exe = app_name or f"PID {pid}", ""
            info = {"pid": pid, "name": name, "exe": exe,
                    "type": app_type, "reasons": []}
            result[pid] = info
        if reason not in info["reasons"]:
            info["reasons"].append(reason)

    # 1) 파일 단위 잠금 (Restart Manager)
    if os.path.isfile(target):
        files = [target]
    else:
        files = []
        for root, _dirs, names in os.walk(target):
            for n in names:
                files.append(os.path.join(root, n))
                if len(files) >= MAX_FILES_SCAN:
                    break
            if len(files) >= MAX_FILES_SCAN:
                break
    for i in range(0, len(files), CHUNK):
        for pid, app, typ in _rm_lockers(files[i:i + CHUNK]):
            add(pid, "파일을 열어서 사용 중", typ, app)

    # 2) 폴더: 작업 폴더로 쓰거나, 폴더 안의 프로그램/DLL을 실행 중인 프로세스
    if os.path.isdir(target):
        for p in psutil.process_iter(["pid", "cwd", "exe"]):
            try:
                if p.info["cwd"] and _is_under(p.info["cwd"], target):
                    add(p.info["pid"], "이 폴더를 작업 폴더로 사용 중")
                if p.info["exe"] and _is_under(p.info["exe"], target):
                    add(p.info["pid"], "이 폴더 안의 프로그램을 실행 중")
            except (psutil.Error, OSError):
                continue
    return result


# ---------------------------------------------------------------- GUI
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(path=""):
    params = " ".join(f'"{a}"' for a in sys.argv if a)
    if getattr(sys, "frozen", False):  # PyInstaller exe
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        exe = sys.executable
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)


class App(tk.Tk):
    def __init__(self, initial_path=None):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("860x520")
        self.minsize(720, 420)
        self.lockers = {}
        self._build()
        if initial_path:
            self.path_var.set(initial_path)
            self.scan()

    def _build(self):
        pad = {"padx": 10, "pady": 6}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)
        ttk.Label(top, text="1. 삭제가 안 되는 파일/폴더를 고르세요").pack(anchor="w")
        row = ttk.Frame(top)
        row.pack(fill="x", pady=4)
        self.path_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.path_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self.scan())
        ttk.Button(row, text="파일 선택", command=self.pick_file).pack(side="left", padx=(6, 0))
        ttk.Button(row, text="폴더 선택", command=self.pick_folder).pack(side="left", padx=(6, 0))
        ttk.Button(row, text="🔍 확인", command=self.scan).pack(side="left", padx=(6, 0))

        ttk.Label(self, text="2. 붙잡고 있는 프로그램 (선택해서 종료하세요)").pack(anchor="w", padx=10)
        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, **pad)
        cols = ("name", "pid", "type", "reason", "exe")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", selectmode="extended")
        for c, t, w in (("name", "프로그램", 150), ("pid", "PID", 60), ("type", "종류", 110),
                        ("reason", "이유", 200), ("exe", "실행 경로", 320)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        btns = ttk.Frame(self)
        btns.pack(fill="x", **pad)
        ttk.Button(btns, text="선택한 프로그램 종료", command=lambda: self.kill(False)).pack(side="left")
        ttk.Button(btns, text="강제 종료", command=lambda: self.kill(True)).pack(side="left", padx=6)
        ttk.Button(btns, text="전부 종료", command=self.kill_all).pack(side="left")
        ttk.Button(btns, text="🗑 파일/폴더 삭제", command=self.delete_target).pack(side="right")

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=10, pady=(0, 8))
        self.status = tk.StringVar(value="파일이나 폴더를 선택하고 '확인'을 눌러주세요.")
        ttk.Label(bottom, textvariable=self.status).pack(side="left")
        if not is_admin():
            ttk.Button(bottom, text="🛡 관리자 권한으로 다시 실행",
                       command=self.run_admin).pack(side="right")

    # ----- actions
    def pick_file(self):
        p = filedialog.askopenfilename(title="파일 선택")
        if p:
            self.path_var.set(os.path.normpath(p))
            self.scan()

    def pick_folder(self):
        p = filedialog.askdirectory(title="폴더 선택")
        if p:
            self.path_var.set(os.path.normpath(p))
            self.scan()

    def run_admin(self):
        relaunch_as_admin()
        self.destroy()

    def scan(self):
        target = self.path_var.get().strip().strip('"')
        if not target or not os.path.exists(target):
            messagebox.showwarning("알림", "존재하는 파일/폴더 경로를 선택해주세요.")
            return
        self.status.set("검사 중입니다... (폴더가 크면 시간이 좀 걸려요)")
        self.tree.delete(*self.tree.get_children())
        threading.Thread(target=self._scan_worker, args=(target,), daemon=True).start()

    def _scan_worker(self, target):
        try:
            res = find_lockers(target)
            self.after(0, self._show, res)
        except Exception as e:
            self.after(0, lambda: self.status.set(f"검사 실패: {e}"))

    def _show(self, res):
        self.lockers = res
        self.tree.delete(*self.tree.get_children())
        for pid, i in res.items():
            self.tree.insert("", "end", iid=str(pid),
                             values=(i["name"], pid, i["type"], " / ".join(i["reasons"]), i["exe"]))
        if res:
            self.status.set(f"{len(res)}개 프로그램이 사용 중입니다.")
        else:
            msg = "붙잡고 있는 프로그램을 찾지 못했어요."
            if not is_admin():
                msg += " (관리자 권한으로 실행하면 더 많이 찾을 수 있어요)"
            self.status.set(msg)

    def _terminate(self, pid, force):
        info = self.lockers.get(pid, {})
        name = info.get("name", str(pid)).lower()
        if pid <= 4 or name in PROTECTED:
            return False, f"{info.get('name', pid)}: 시스템 핵심 프로세스라 종료할 수 없습니다."
        try:
            p = psutil.Process(pid)
            if force:
                p.kill()
            else:
                p.terminate()
            try:
                p.wait(3)
            except psutil.TimeoutExpired:
                return False, f"{info.get('name', pid)}: 아직 종료되지 않았어요. '강제 종료'를 써보세요."
            return True, ""
        except psutil.NoSuchProcess:
            return True, ""
        except psutil.AccessDenied:
            return False, f"{info.get('name', pid)}: 권한이 부족합니다. 관리자 권한으로 다시 실행해보세요."
        except Exception as e:
            return False, f"{info.get('name', pid)}: {e}"

    def _kill_pids(self, pids, force):
        if not pids:
            messagebox.showinfo("알림", "종료할 프로그램을 목록에서 선택해주세요.")
            return
        names = ", ".join(self.lockers[p]["name"] for p in pids if p in self.lockers)
        warn = ""
        if any(self.lockers[p]["name"].lower() == "explorer.exe" for p in pids if p in self.lockers):
            warn = "\n\n※ 탐색기(explorer.exe)를 종료하면 작업표시줄이 잠깐 사라질 수 있어요."
        if not messagebox.askyesno("종료 확인",
                                   f"다음 프로그램을 {'강제 ' if force else ''}종료할까요?\n\n{names}\n\n"
                                   f"저장하지 않은 작업은 사라질 수 있습니다.{warn}"):
            return
        errors = []
        for pid in pids:
            ok, err = self._terminate(pid, force)
            if not ok:
                errors.append(err)
        if errors:
            messagebox.showwarning("일부 실패", "\n".join(errors))
        self.scan()

    def kill(self, force):
        self._kill_pids([int(i) for i in self.tree.selection()], force)

    def kill_all(self):
        self._kill_pids(list(self.lockers.keys()), False)

    def delete_target(self):
        target = self.path_var.get().strip().strip('"')
        if not target or not os.path.exists(target):
            messagebox.showwarning("알림", "삭제할 경로가 없습니다.")
            return
        if not messagebox.askyesno("삭제 확인",
                                   f"정말 삭제할까요? 휴지통으로 가지 않고 바로 지워집니다.\n\n{target}",
                                   icon="warning"):
            return
        try:
            if os.path.isdir(target):
                shutil.rmtree(target)
            else:
                os.remove(target)
            messagebox.showinfo("완료", "삭제했습니다.")
            self.path_var.set("")
            self.tree.delete(*self.tree.get_children())
            self.status.set("삭제 완료!")
        except PermissionError:
            messagebox.showerror("삭제 실패",
                                 "아직 사용 중이거나 권한이 없습니다.\n'확인'으로 다시 검사해보세요.")
        except Exception as e:
            messagebox.showerror("삭제 실패", str(e))


def main():
    if os.name != "nt":
        print("이 도구는 Windows 전용입니다.")
        sys.exit(1)
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    App(initial).mainloop()


if __name__ == "__main__":
    main()
