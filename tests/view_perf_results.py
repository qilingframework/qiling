import sys
import os
import io
import pstats
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox as msgbox
from tkinter import scrolledtext

class QLGuiPerfApp():
    def __init__(self):
        self.root = Tk()
        self.root.minsize(1024, 384)
        self.root.title("QL Perf Results Viewer")

        self.menu = Menu(self.root)

        self.file_open = Menu(self.menu, tearoff=0)
        self.file_open.add_command(label="Open", command=self.open_perf_file)
        self.file_open.add_command(label="Exit", command=sys.exit)

        self.menu.add_cascade(label="File", menu=self.file_open)
        self.root.config(menu=self.menu)

        self.scrollData = scrolledtext.ScrolledText(self.root, wrap=WORD)
        self.scrollData.pack(fill=BOTH, expand=True)
        self.scrollData.tag_configure("qiling_highlight", foreground="yellow", background="green")
        self.root.mainloop()
        
    def open_perf_file(self):
        filename = filedialog.askopenfilename(initialdir=".", title="Select a perf file"
        ,filetypes=(("perf files", "*.perf"),) )
        
        try:
            output_stream = io.StringIO()
            stats = pstats.Stats(filename, stream=output_stream)
            stats.print_stats()
            self.scrollData.delete(1.0, END)
            self.scrollData.insert(INSERT, output_stream.getvalue())
            self.highlight_pattern("qiling_highlight", "qiling")
        except Exception as e:
            print(e)
            msgbox.showerror("Error...", "Unable to load selected file")

    def highlight_pattern(self, tag, keyword):
        start = self.scrollData.index("1.0")
        end = self.scrollData.index("end")
        self.scrollData.mark_set("matchStart", start)
        self.scrollData.mark_set("matchEnd", start)
        self.scrollData.mark_set("searchLimit", end)
        count = IntVar()
        while True:
            index = self.scrollData.search(keyword, "matchEnd", "searchLimit", count=count, regexp=False)
            if index == "": break
            if count.get() == 0: break
            self.scrollData.mark_set("matchStart", index)
            self.scrollData.mark_set("matchEnd", "%s+%sc" % (index, count.get() ))
            self.scrollData.tag_add(tag, "matchStart", "matchEnd")


def console_print(filename):
    try:
        stats = pstats.Stats(filename)
        stats.print_stats()
    except:
        print("Failed to load perf file => {}".format(filename))

def usage():
    print("View performance results from Qiling test runs")
    print("----------------------------------------------")
    print("{} --gui             : Launch in gui mode".format(sys.argv[0]))
    print("{} input_file.perf   : Print contents of perf file".format(sys.argv[0]))

def main():
    if len(sys.argv) == 2:
        if sys.argv[1] == "--gui":
            QLGuiPerfApp()
            sys.exit(0)
        elif os.path.isfile(sys.argv[1]):
            console_print(sys.argv[1])
            sys.exit(0)

    usage()

if __name__ == "__main__":
    main()