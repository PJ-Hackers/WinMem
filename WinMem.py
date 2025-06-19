import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ctypes
from ctypes import wintypes
import psutil
import threading
import datetime
import re

# Ensure running on Windows platform
if os.name != 'nt':
    messagebox.showerror("Unsupported OS", "This application runs only on Windows.")
    sys.exit(1)

# Windows API Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle

TerminateProcess = kernel32.TerminateProcess
TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
TerminateProcess.restype = wintypes.BOOL

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       wintypes.LPVOID),
        ("AllocationBase",    wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t
]
VirtualQueryEx.restype = ctypes.c_size_t

class MemoryEditorApp:
    PAGE_SIZE = 256  # bytes per memory read page

    def __init__(self, root):
        self.root = root
        self.root.title("Windows Memory Viewer & Editor with Subprocesses")
        self.selected_pid = None
        self.process_handle = None
        self.memory_regions = []
        self.all_procs = []
        self.proc_tree_items = {}  # pid -> tree item id
        self.current_mem_page = 0
        self.current_region_size = 0
        self.current_region_base = 0

        self.create_widgets()
        self.populate_processes()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        # Processes frame
        self.proc_frame = ttk.LabelFrame(self.root, text="Processes (Click + to expand subprocesses)")
        self.proc_frame.pack(fill='both', expand=True, padx=5, pady=5)

        top_controls = ttk.Frame(self.proc_frame)
        top_controls.pack(fill='x')

        self.proc_search = ttk.Entry(top_controls)
        self.proc_search.pack(side='left', fill='x', expand=True, padx=5)
        self.proc_search.bind("<KeyRelease>", self.filter_process_list)

        self.sort_option = ttk.Combobox(top_controls, values=["Name", "PID", "Recently Opened"], state="readonly", width=15)
        self.sort_option.set("Name")
        self.sort_option.pack(side='left', padx=5)
        self.sort_option.bind("<<ComboboxSelected>>", lambda e: self.populate_processes())

        self.refresh_proc_btn = ttk.Button(top_controls, text="Refresh Processes", command=self.populate_processes)
        self.refresh_proc_btn.pack(side='left', padx=5)

        self.kill_proc_btn = ttk.Button(top_controls, text="Kill Selected Process", command=self.kill_selected_process, state='disabled')
        self.kill_proc_btn.pack(side='left', padx=5)

        # Process treeview for hierarchical processes
        self.process_list = ttk.Treeview(self.proc_frame, columns=("PID", "Started"), show='tree headings')
        self.process_list.heading("#0", text="Process Name")
        self.process_list.heading("PID", text="PID")
        self.process_list.heading("Started", text="Started")
        self.process_list.column("#0", width=300)
        self.process_list.column("PID", width=80, anchor='center')
        self.process_list.column("Started", width=140, anchor='center')
        self.process_list.pack(fill='both', expand=True, side='left')

        vsb1 = ttk.Scrollbar(self.proc_frame, orient="vertical", command=self.process_list.yview)
        self.process_list.configure(yscrollcommand=vsb1.set)
        vsb1.pack(side='left', fill='y')

        self.process_list.bind("<<TreeviewSelect>>", self.on_process_select)
        self.process_list.bind("<<TreeviewOpen>>", self.on_tree_item_expand)

        # Memory Regions frame
        self.mem_frame = ttk.LabelFrame(self.root, text="Memory Regions")
        self.mem_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.mem_tree_frame = ttk.Frame(self.mem_frame)
        self.mem_tree_frame.pack(fill='both', expand=True)

        self.memory_tree = ttk.Treeview(self.mem_tree_frame, columns=("Base Address", "Size"), show='headings')
        self.memory_tree.heading("Base Address", text="Base Address")
        self.memory_tree.heading("Size", text="Size")
        self.memory_tree.pack(side='left', fill='both', expand=True)

        vsb2 = ttk.Scrollbar(self.mem_tree_frame, orient="vertical", command=self.memory_tree.yview)
        self.memory_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side='left', fill='y')

        self.memory_tree.bind("<<TreeviewSelect>>", self.on_memory_select)
        self.memory_tree.bind("<Double-1>", self.open_memory_editor)

        self.mem_refresh_btn = ttk.Button(self.mem_frame, text="Refresh Memory Regions", command=self.enumerate_memory_regions_thread)
        self.mem_refresh_btn.pack(pady=3)

        # Hex display & paging controls
        hex_frame = ttk.LabelFrame(self.root, text="Memory Content (256 bytes per page)")
        hex_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.hex_display = scrolledtext.ScrolledText(hex_frame, height=10, font=('Consolas', 10))
        self.hex_display.pack(fill='both', padx=5, pady=5)

        nav_frame = ttk.Frame(hex_frame)
        nav_frame.pack(fill='x', padx=5, pady=3)
        self.page_info_lbl = ttk.Label(nav_frame, text="Page: 0")
        self.page_info_lbl.pack(side='left')

        self.prev_page_btn = ttk.Button(nav_frame, text="Previous Page", command=self.prev_mem_page)
        self.prev_page_btn.pack(side='right', padx=5)
        self.next_page_btn = ttk.Button(nav_frame, text="Next Page", command=self.next_mem_page)
        self.next_page_btn.pack(side='right', padx=5)

        # Style tag for system processes
        self.process_list.tag_configure("system_proc", background="#FBB117")

    def populate_processes(self):
        def task():
            # Get all processes info
            procs = []
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'create_time']):
                try:
                    start = datetime.datetime.fromtimestamp(proc.info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
                    procs.append({
                        'pid': proc.info['pid'],
                        'ppid': proc.info['ppid'],
                        'name': proc.info['name'],
                        'start': start,
                        'create_time': proc.info['create_time']
                    })
                except Exception:
                    continue

            sort_by = self.sort_option.get()
            if sort_by == "Name":
                procs.sort(key=lambda x: x['name'].lower())
            elif sort_by == "PID":
                procs.sort(key=lambda x: x['pid'])
            elif sort_by == "Recently Opened":
                procs.sort(key=lambda x: x['create_time'], reverse=True)

            # Build dict of pid -> children
            children_map = {}
            for p in procs:
                children_map.setdefault(p['ppid'], []).append(p)

            # Store for filtering and access
            self.all_procs = procs
            self.children_map = children_map

            # Clear treeview
            self.root.after(0, self.display_process_tree)

        threading.Thread(target=task, daemon=True).start()

    def display_process_tree(self):
        # Clear existing items
        self.process_list.delete(*self.process_list.get_children())
        self.proc_tree_items.clear()
        self.selected_pid = None
        self.kill_proc_btn.config(state='disabled')

        # We want to show only root processes at first (ppid == 0 or no parent)
        root_procs = [p for p in self.all_procs if p['ppid'] == 0 or p['ppid'] not in {proc['pid'] for proc in self.all_procs}]
        filter_term = self.proc_search.get().lower()

        def add_proc_tree_item(proc, parent=''):
            # If filter active, skip those not matching (by name or PID)
            if filter_term and filter_term not in proc['name'].lower() and filter_term not in str(proc['pid']):
                # but maybe some children match? Then must show parent anyway to allow expanding
                # We won't filter children here for simplicity; user can expand to see.
                return None

            tag = ""
            try:
                p = psutil.Process(proc['pid'])
                username = p.username().lower()
                if any(s in username for s in ("system", "local service", "network service")):
                    tag = "system_proc"
            except Exception:
                pass

            started = proc['start']
            item_id = self.process_list.insert(parent, 'end', text=proc['name'], values=(proc['pid'], started), tags=(tag,))

            self.proc_tree_items[proc['pid']] = item_id

            # Add a dummy child if this process has children so user can expand
            if proc['pid'] in self.children_map:
                # Insert dummy to show expand arrow
                self.process_list.insert(item_id, 'end', text='Loading...', values=('', ''))

            return item_id

        for proc in root_procs:
            add_proc_tree_item(proc)

    def filter_process_list(self, event=None):
        self.populate_processes()  # Rebuild entire tree with filter

    def on_tree_item_expand(self, event):
        # When user expands a tree item, load children dynamically
        selected = self.process_list.focus()
        if not selected:
            return

        # Check if dummy child exists (means not loaded yet)
        children = self.process_list.get_children(selected)
        if len(children) == 1:
            child_text = self.process_list.item(children[0], 'text')
            if child_text == 'Loading...':
                # Remove dummy
                self.process_list.delete(children[0])
                # Load real children
                # Find PID by reverse lookup
                pid = None
                for k, v in self.proc_tree_items.items():
                    if v == selected:
                        pid = k
                        break
                if pid and pid in self.children_map:
                    for child_proc in self.children_map[pid]:
                        self.add_child_process(selected, child_proc)

    def add_child_process(self, parent_item, proc):
        tag = ""
        try:
            p = psutil.Process(proc['pid'])
            username = p.username().lower()
            if any(s in username for s in ("system", "local service", "network service")):
                tag = "system_proc"
        except Exception:
            pass

        item_id = self.process_list.insert(parent_item, 'end', text=proc['name'], values=(proc['pid'], proc['start']), tags=(tag,))
        self.proc_tree_items[proc['pid']] = item_id

        if proc['pid'] in self.children_map:
            self.process_list.insert(item_id, 'end', text='Loading...', values=('', ''))

    def on_process_select(self, event):
        sel = self.process_list.selection()
        if not sel:
            self.selected_pid = None
            self.kill_proc_btn.config(state='disabled')
            return
        item = sel[0]
        pid_val = self.process_list.set(item, "PID")
        if not pid_val or pid_val == '':
            self.selected_pid = None
            self.kill_proc_btn.config(state='disabled')
            return
        try:
            pid = int(pid_val)
        except:
            self.selected_pid = None
            self.kill_proc_btn.config(state='disabled')
            return
        self.selected_pid = pid
        self.kill_proc_btn.config(state='normal')
        self.open_process_handle()
        self.enumerate_memory_regions_thread()

    def open_process_handle(self):
        if self.process_handle:
            CloseHandle(self.process_handle)
            self.process_handle = None
        if not self.selected_pid:
            return
        desired_access = (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)
        self.process_handle = OpenProcess(desired_access, False, self.selected_pid)
        if not self.process_handle:
            messagebox.showerror("Error", f"Failed to open process PID {self.selected_pid}. You may need to run as Administrator.")
            self.selected_pid = None
            self.kill_proc_btn.config(state='disabled')
        else:
            # Clear previous memory regions & hex
            self.memory_regions.clear()
            self.memory_tree.delete(*self.memory_tree.get_children())
            self.hex_display.delete('1.0', tk.END)
            self.current_mem_page = 0
            self.current_region_size = 0
            self.current_region_base = 0

    def enumerate_memory_regions_thread(self):
        if not self.process_handle:
            return
        self.mem_refresh_btn.config(state='disabled')
        threading.Thread(target=self.enumerate_memory_regions, daemon=True).start()

    def enumerate_memory_regions(self):
        # Enumerate memory regions in the selected process
        regions = []
        addr = 0
        max_address = 0x7FFFFFFF_FFFFFFFF  # 64-bit max address approx
        mbi = MEMORY_BASIC_INFORMATION()
        while addr < max_address:
            ret = VirtualQueryEx(self.process_handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if ret == 0:
                break

            if mbi.State == MEM_COMMIT and (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)):
                base = ctypes.addressof(mbi.BaseAddress.contents) if hasattr(mbi.BaseAddress, 'contents') else ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value
                if base is None:
                    base = addr
                size = mbi.RegionSize
                regions.append((base, size))
            # Move to next region
            addr = addr + mbi.RegionSize

        self.memory_regions = regions
        self.root.after(0, self.update_memory_regions_list)

    def update_memory_regions_list(self):
        self.memory_tree.delete(*self.memory_tree.get_children())
        for base, size in self.memory_regions:
            self.memory_tree.insert('', 'end', values=(f"0x{base:016X}", f"{size} bytes"))
        self.mem_refresh_btn.config(state='normal')
        self.hex_display.delete('1.0', tk.END)
        self.current_mem_page = 0
        self.current_region_size = 0
        self.current_region_base = 0
        self.page_info_lbl.config(text="Page: 0")

    def on_memory_select(self, event):
        sel = self.memory_tree.selection()
        if not sel:
            return
        item = sel[0]
        base_hex = self.memory_tree.set(item, "Base Address")
        size_str = self.memory_tree.set(item, "Size")
        base = int(base_hex, 16)
        size = int(size_str.split()[0])
        self.current_region_base = base
        self.current_region_size = size
        self.current_mem_page = 0
        self.read_and_display_memory_page()

    def read_and_display_memory_page(self):
        if not self.process_handle or self.current_region_base == 0:
            return

        offset = self.current_mem_page * self.PAGE_SIZE
        if offset >= self.current_region_size:
            # Out of range
            return

        to_read = min(self.PAGE_SIZE, self.current_region_size - offset)
        buffer = (ctypes.c_ubyte * to_read)()
        bytesRead = ctypes.c_size_t(0)
        success = ReadProcessMemory(self.process_handle, ctypes.c_void_p(self.current_region_base + offset), buffer, to_read, ctypes.byref(bytesRead))
        if not success or bytesRead.value == 0:
            self.hex_display.delete('1.0', tk.END)
            self.hex_display.insert(tk.END, "[Failed to read memory or access denied]")
            self.page_info_lbl.config(text=f"Page: {self.current_mem_page+1} (Failed to read)")
            return

        data = bytes(buffer[:bytesRead.value])
        hex_lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
            ascii_bytes = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f"{self.current_region_base + offset + i:016X}:  {hex_bytes:<47}  {ascii_bytes}")

        self.hex_display.delete('1.0', tk.END)
        self.hex_display.insert(tk.END, '\n'.join(hex_lines))
        self.page_info_lbl.config(text=f"Page: {self.current_mem_page + 1} of {(self.current_region_size + self.PAGE_SIZE -1)//self.PAGE_SIZE}")

    def prev_mem_page(self):
        if self.current_mem_page > 0:
            self.current_mem_page -= 1
            self.read_and_display_memory_page()

    def next_mem_page(self):
        if (self.current_mem_page + 1) * self.PAGE_SIZE < self.current_region_size:
            self.current_mem_page += 1
            self.read_and_display_memory_page()

    def open_memory_editor(self, event=None):
        # Open dialog to edit memory at current page
        if not self.process_handle or self.current_region_base == 0:
            return

        offset = self.current_mem_page * self.PAGE_SIZE
        to_read = min(self.PAGE_SIZE, self.current_region_size - offset)
        buffer = (ctypes.c_ubyte * to_read)()
        bytesRead = ctypes.c_size_t(0)
        success = ReadProcessMemory(self.process_handle, ctypes.c_void_p(self.current_region_base + offset), buffer, to_read, ctypes.byref(bytesRead))
        if not success or bytesRead.value == 0:
            messagebox.showerror("Error", "Failed to read memory for editing.")
            return

        data = bytes(buffer[:bytesRead.value])

        edit_win = tk.Toplevel(self.root)
        edit_win.title(f"Edit Memory 0x{self.current_region_base + offset:016X} (+{offset})")

        text = scrolledtext.ScrolledText(edit_win, width=70, height=15, font=('Consolas', 10))
        text.pack(padx=10, pady=10)

        # Insert hex data only (without addresses)
        hex_str = ' '.join(f"{b:02X}" for b in data)
        text.insert('1.0', hex_str)

        def save_changes():
            new_hex_str = text.get('1.0', 'end').strip()
            # Validate input: hex bytes separated by spaces
            new_hex_str = re.sub(r'\s+', ' ', new_hex_str)
            hex_bytes = new_hex_str.split(' ')
            if len(hex_bytes) != bytesRead.value:
                messagebox.showerror("Error", f"Input length mismatch. Expected {bytesRead.value} bytes.")
                return
            try:
                new_bytes = bytes(int(b, 16) for b in hex_bytes)
            except Exception:
                messagebox.showerror("Error", "Invalid hex input.")
                return

            written = ctypes.c_size_t(0)
            buf = (ctypes.c_ubyte * len(new_bytes))(*new_bytes)
            success = WriteProcessMemory(self.process_handle, ctypes.c_void_p(self.current_region_base + offset), buf, len(new_bytes), ctypes.byref(written))
            if not success or written.value != len(new_bytes):
                messagebox.showerror("Error", "Failed to write memory. Check permissions.")
                return

            messagebox.showinfo("Success", f"Wrote {written.value} bytes to memory.")
            self.read_and_display_memory_page()
            edit_win.destroy()

        btn_frame = ttk.Frame(edit_win)
        btn_frame.pack(pady=5)

        save_btn = ttk.Button(btn_frame, text="Save Changes", command=save_changes)
        save_btn.pack(side='left', padx=5)
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=edit_win.destroy)
        cancel_btn.pack(side='left', padx=5)

    def kill_selected_process(self):
        if not self.selected_pid:
            return
        try:
            p = psutil.Process(self.selected_pid)
            p.terminate()
            p.wait(3)
            messagebox.showinfo("Success", f"Process PID {self.selected_pid} terminated.")
            self.populate_processes()
            self.memory_tree.delete(*self.memory_tree.get_children())
            self.hex_display.delete('1.0', tk.END)
            self.selected_pid = None
            self.kill_proc_btn.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to terminate process: {e}")

    def on_close(self):
        if self.process_handle:
            CloseHandle(self.process_handle)
        self.root.destroy()

def main():
    root = tk.Tk()
    app = MemoryEditorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
