# coding=utf-8
import datetime
import threading
import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview

from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.all import *

# 用来终止抓包线程的线程事件
stop_sending = threading.Event()
# 数据包编号
packet_id = 1
# 已抓到的数据包列表
packet_list =[]
# 暂停抓包标志位
pause_flag = False
# 保存文件标志位
save_flag = False
# 停止抓包标志位
stop_flag=False
# 流量排序暂存过滤项
tmpEntriesInTreeView = []

# 状态栏
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)
    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()
    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()

# 时间戳转为格式化时间
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime

# 格式化时间转为时间戳
def time2timestamp(mytime):
    time_array = time.strptime(mytime, "%Y-%m-%d %H:%M:%S")
    return time.mktime(time_array)

# 数据包列表单击事件响应函数
def on_click_packet_list_tree(event):
    # event.widget获取Treeview对象，调用selection获取选择对象名称,返回结果为字符型元祖
    selected_item = event.widget.selection()
    # 清空packet_dissect_tree上现有的内容
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    # 转换为整型
    packet_id = int(selected_item[0])-1
    # 取出要分析的数据包
    packet = packet_list[packet_id]
    # 通过show()方法解析数据包
    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')  # 删除#
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)  # 第一个参数为空表示根节点
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        # 动态调整协议解析区的宽度
        col_width = font.Font().measure(line)
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)

# 抓取数据包并保存
def capture_packet():
    # 获取过滤条件
    filters = fitler_entry.get()
    # 设置停止抓包的条件stop_filter
    stop_sending.clear()
    global packet_list
    # 清空列表
    packet_list.clear()
    # 抓取数据包并将抓到的包存在列表中
    try:
        sniff(prn=(lambda x: process_packet(x)), filter=filters, stop_filter=(lambda x: stop_sending.is_set()))
    except scapy.error.Scapy_Exception:
        tkinter.messagebox.askyesnocancel("错误", "过滤选项语法有误，请检查")
        start_button['state'] = NORMAL
        pause_button['state'] = DISABLED
        stop_button['state'] = DISABLED
        save_button['state'] = NORMAL

# 处理抓到的数据包
def process_packet(packet):
    if pause_flag == False:
        global packet_list
        # 将抓到的包存在列表中
        packet_list.append(packet)
        # 抓包的时间
        packet_time = timestamp2time(packet.time)
        if Ether in packet:
            src = packet[Ether].src
            dst = packet[Ether].dst
            type = packet[Ether].type
            types = {0x0800:'IPv4',0x0806:'ARP',0x86dd:'IPv6',0x88cc:'LLDP',0x891D:'TTE'}
            if type in types:
                proto = types[type]
            else:
                proto = 'LOOP'  # 协议
            # IP
            if proto == 'IPv4':
                # 建立协议查询字典
                protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89:'OSPF'}
                src = packet[IP].src
                dst = packet[IP].dst
                proto=packet[IP].proto
                if proto in protos:
                    proto = protos[proto]
            # TCP
            if TCP in packet:
                protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                # 获取端口信息
                if sport in protos_tcp:
                    proto = protos_tcp[sport]
                elif dport in protos_tcp:
                    proto = protos_tcp[dport]
            elif UDP in packet:
                if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                    proto = 'DNS'
        else:
            return
            # src = packet[Dot3].src
            # dst = packet[Dot3].dst
            # proto = 'SNAP'    # 802.3
        length = len(packet)  # 长度
        info = packet.summary()  # 信息
        global packet_id  # 数据包的编号
        packet_list_tree.insert("", 'end', packet_id, text=packet_id,
                            values=(packet_id, packet_time, src, dst, proto, length, info))
        packet_list_tree.update_idletasks()  # 更新列表，不需要修改
        packet_id = packet_id + 1

# 将抓到的数据包保存为pcap文件
def save_captured_data_to_file():
    global save_flag
    save_flag = True
    filename=tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'),
                                                                           ('数据包', '.pcap')], initialfile='.pcap')
    if filename.find('.pcap') == -1:
        filename = filename+'.pcap'
    wrpcap(filename, packet_list)

# 开始按钮单击响应函数
def start_capture():
    global pause_flag,stop_flag,save_flag,packet_list
    # 已经停止，重新开始抓包但没进行保存操作
    if stop_flag is True and save_flag is False and packet_list != []:
        result = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
        if result is True:
            filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'),
                                                                                     ('数据包', '.pcap')], initialfile='.pcap')
            if filename.find('.pcap') == -1:
                filename = filename + '.pcap'
            wrpcap(filename, packet_list)
        else:
            stop_flag = False
            return
    # 设置开始按钮为不可用，暂停按钮可操作
    start_button['state'] = DISABLED
    save_button['state'] = DISABLED
    pause_button['state'] = NORMAL
    stop_button['state'] = NORMAL
    packet_sorter_start_button['state'] = DISABLED
    packet_sorter_end_button['state'] = DISABLED
    stop_flag = False
    if pause_flag is False:
        # 清空已经抓到的数据包列表--------------
        items = packet_list_tree.get_children()
        for item in items:
            packet_list_tree.delete(item)
        packet_list_tree.clipboard_clear()
        global packet_id
        packet_id = 1
        # 开启新线程进行抓包
        t = threading.Thread(target=capture_packet)
        t.setDaemon(True)
        t.start()
        save_flag = False
    else:
        pause_flag = False

# 暂停按钮单击响应函数
def pause_capture():
    start_button['state'] = NORMAL
    pause_button['state'] = DISABLED
    packet_sorter_start_button['state'] = NORMAL
    global pause_flag
    pause_flag = True

# 停止按钮单击响应函数
def stop_capture():
    # 终止线程，停止抓包
    stop_sending.set()
    # 设置开始按钮为可用，暂停按钮为不可用，保存为可用
    start_button['state'] = NORMAL
    pause_button['state'] = DISABLED
    stop_button['state'] = DISABLED
    save_button['state'] = NORMAL
    packet_sorter_start_button['state'] = NORMAL
    global pause_flag, stop_flag
    pause_flag = False
    stop_flag = True

# 退出按钮单击响应函数
def quit_program():
    #终止线程，停止抓包
    stop_sending.set()
    # 已经暂停，或停止，需要提示保存在退出
    if stop_flag is True or pause_flag is True:
        # 没进行保存操作
        if save_flag is False:
            result = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
            if result is False:
                tk.destroy()
            elif result is True:
                filename = tkinter.filedialog.asksaveasfilename(title='保存文件',
                                                                filetypes=[('所有文件', '.*'), ('数据包', '.pcap')],initialfile='.pcap')
                if filename.find('.pcap') == -1:
                    filename = filename + '.pcap'
                wrpcap(filename, packet_list)
                tk.destroy()
        else:
            tk.destroy()
    else:
        tk.destroy()

# 流量排序功能函数
def packet_sort_start():
    packet_sorter_end_button['state'] = NORMAL
    packet_sorter_start_button['state'] = DISABLED
    start_button['state'] = DISABLED
    proto = sorter_entry_proto.get()
    src = sorter_entry_src.get()
    dst = sorter_entry_dst.get()
    starttime = sorter_entry_starttime.get()
    endtime = sorter_entry_endtime.get()
    listOfEntriesInTreeView = packet_list_tree.get_children()
    for each in listOfEntriesInTreeView:
        # 加入暂存数据包列表中，用于后续恢复
        tmpEntriesInTreeView.append(packet_list_tree.item(each))
        if not verify(packet_list_tree.item(each)['values'],  proto, src, dst, starttime, endtime):
            # 临时删除不符合要求的数据包
            packet_list_tree.delete(each)
    packet_list_tree.update_idletasks()

# 流量排序结束函数
def packet_sort_end():
    packet_sorter_start_button['state'] = NORMAL
    packet_sorter_end_button['state'] = DISABLED
    start_button['state'] = NORMAL
    tmp = packet_list_tree.get_children()
    # 清空数据包列表
    for t in tmp:
        packet_list_tree.delete(t)
    # 利用暂存的数据包列表进行恢复
    for tmpEntry in tmpEntriesInTreeView:
        packet_list_tree.insert("", 'end', tmpEntry['values'][0], text=tmpEntry['text'], values=tmpEntry['values'])
    tmpEntriesInTreeView.clear()
    packet_list_tree.update_idletasks()

# 审核过滤条件
def verify(values, proto, src, dst, start, end):
    if proto and values[4] != proto:
        return False
    elif src and values[2] != src:
        return False
    elif dst and values[3] != dst:
        return False
    elif start and time2timestamp(start) > time2timestamp(values[1]):
        return False
    elif end and time2timestamp(end) < time2timestamp(values[1]):
        return False
    else:
        return True

# ---------------------GUI界面---------------------
tk = tkinter.Tk()
tk.title("网络嗅探器")

# 主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF Filters :")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包排序区
packet_sorter = Frame()
packet_sorter_start_button = Button(packet_sorter, width=10, text="流量排序", command=packet_sort_start)
packet_sorter_end_button = Button(packet_sorter, width=6, text="结束", command=packet_sort_end)
sorter_label_proto = Label(packet_sorter, width=5, text="协议 :")
sorter_entry_proto = Entry(packet_sorter, width=17)
sorter_label_src = Label(packet_sorter, width=3, text="Src :")
sorter_entry_src = Entry(packet_sorter, width=22)
sorter_label_dst = Label(packet_sorter, width=3, text="Dst :")
sorter_entry_dst = Entry(packet_sorter, width=22)
sorter_label_time = Label(packet_sorter, width=9, text="Time from :")
sorter_entry_starttime = Entry(packet_sorter, width=21)
sorter_label_horizon = Label(packet_sorter, width=3, text="to")
sorter_entry_endtime = Entry(packet_sorter, width=21)
packet_sorter_start_button['state'] = 'disable'
packet_sorter_end_button['state'] = 'disable'
packet_sorter_start_button.pack(side=LEFT, padx=5)
packet_sorter_end_button.pack(side=LEFT, after=packet_sorter_start_button, padx=9)
sorter_label_proto.pack(side=LEFT, after=packet_sorter_end_button, padx=7)
sorter_entry_proto.pack(side=LEFT, after=sorter_label_proto, padx=1, pady=7)
sorter_label_src.pack(side=LEFT, after=sorter_entry_proto, padx=14, pady=7)
sorter_entry_src.pack(side=LEFT, after=sorter_label_src, padx=1, pady=7)
sorter_label_dst.pack(side=LEFT, after=sorter_entry_src, padx=14, pady=7)
sorter_entry_dst.pack(side=LEFT, after=sorter_label_dst, padx=1, pady=7)
sorter_label_time.pack(side=LEFT, after=sorter_entry_dst, padx=14, pady=7)
sorter_entry_starttime.pack(side=LEFT, after=sorter_label_time, padx=1, pady=7)
sorter_label_horizon.pack(side=LEFT, after=sorter_entry_starttime, padx=2, pady=7)
sorter_entry_endtime.pack(side=LEFT, after=sorter_label_horizon, padx=2, pady=7)
packet_sorter.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse') # 选择数据表

packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [30, 170, 140, 140, 80, 80, 560]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='数据表解析', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=X, expand=YES)
# 垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 加入到主窗体
main_panedwindow.add(packet_dissect_frame)

main_panedwindow.pack(fill=BOTH, expand=1)
# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
# 主逻辑
tk.mainloop()