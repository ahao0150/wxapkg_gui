import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import re
import struct
import threading
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import requests
import json

class WxapkgUnpacker:
    def __init__(self, root):
        self.root = root
        self.root.title("微信小程序解包工具")
        self.root.geometry("1344x720")
        
        # 初始化数据
        self.wxid_infos = []
        self.selected_wxid = None
        self.output_dir = None  # 添加输出目录变量
        
        # 设置默认扫描目录
        self.default_scan_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'WeChat Files', 'Applet')
        
        # 添加缓存文件路径
        self.cache_file = "wxid.json"
        self.wxid_cache = self.load_wxid_cache()
        
        # 创建UI组件
        self.create_widgets()
        
    def create_widgets(self):
        # 顶部工具栏
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        self.scan_btn = ttk.Button(toolbar, text="扫描目录", command=self.scan_directory)
        self.scan_btn.pack(side=tk.LEFT, padx=2)
        
        self.unpack_btn = ttk.Button(toolbar, text="解包选中", command=self.unpack_selected, state=tk.DISABLED)
        self.unpack_btn.pack(side=tk.LEFT, padx=2)
        
        # 主内容区域
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 小程序列表
        self.tree = ttk.Treeview(main_frame, columns=('nickname', 'developer', 'description'), show='headings')
        self.tree.heading('nickname', text='名称')
        self.tree.heading('developer', text='开发者') 
        self.tree.heading('description', text='描述')
        self.tree.column('nickname', width=200)
        self.tree.column('developer', width=250)
        self.tree.column('description', width=300)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 详情面板
        detail_frame = ttk.Frame(main_frame)
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5)
        
        # 添加输出目录显示和编辑功能
        output_frame = ttk.Frame(detail_frame)
        output_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(output_frame, text="输出目录:").pack(side=tk.LEFT)
        self.output_entry = ttk.Entry(output_frame)
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        
        self.browse_btn = ttk.Button(output_frame, text="浏览", command=self.browse_output)
        self.browse_btn.pack(side=tk.RIGHT)
        
        # 在输出目录框架下添加压缩选项
        compress_frame = ttk.Frame(detail_frame)
        compress_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.compress_var = tk.BooleanVar(value=False)
        self.compress_checkbox = ttk.Checkbutton(
            compress_frame, 
            text="压缩JS/JSON文件", 
            variable=self.compress_var
        )
        self.compress_checkbox.pack(side=tk.LEFT)
        
        # 在压缩选项框架中添加图片压缩选项
        self.compress_png_var = tk.BooleanVar(value=False)
        self.compress_png_checkbox = ttk.Checkbutton(
            compress_frame, 
            text="压缩PNG图片", 
            variable=self.compress_png_var
        )
        self.compress_png_checkbox.pack(side=tk.LEFT, padx=(10, 0))
        
        self.detail_text = tk.Text(detail_frame, wrap=tk.WORD, height=15)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        
        # 进度条
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        # 绑定事件
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        
    def scan_directory(self):
        # 使用默认目录作为初始目录
        path = filedialog.askdirectory(initialdir=self.default_scan_dir)
        if not path:
            return
            
        self.wxid_infos = []
        self.tree.delete(*self.tree.get_children())
        
        # 在后台线程执行扫描
        threading.Thread(target=self.do_scan, args=(path,)).start()
        
    def do_scan(self, path):
        try:
            reg_appid = re.compile(r'(wx[0-9a-f]{16})')
            for entry in os.scandir(path):
                if entry.is_dir() and reg_appid.match(entry.name):
                    wxid = reg_appid.findall(entry.name)[0]
                    info = self.query_wxid_info(wxid)
                    info['location'] = entry.path
                    self.wxid_infos.append(info)
                    
                    # 更新UI
                    self.root.after(0, self.update_tree, info)
                    
        except Exception as e:
            self.root.after(0, messagebox.showerror, "扫描错误", str(e))
            
    def load_wxid_cache(self):
        """加载wxid缓存"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"加载缓存失败: {str(e)}")
        return {}

    def save_wxid_cache(self):
        """保存wxid缓存"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.wxid_cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存缓存失败: {str(e)}")

    def query_wxid_info(self, wxid):
        """查询小程序信息，支持缓存"""
        # 先检查缓存
        if wxid in self.wxid_cache:
            return self.wxid_cache[wxid]

        try:
            # 尝试从网络获取信息
            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            data = {'appid': wxid}
            response = requests.post(
                'https://kainy.cn/api/weapp/info/',
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                if result['code'] == 0:
                    print(result)
                    info = {
                        'wxid': wxid,
                        'nickname': result['data']['nickname'] or wxid,
                        'principal_name': result['data']['principal_name'] or '未知开发者',
                        'description': result['data']['description'] or '无描述信息'
                    }
                    # 保存到缓存
                    self.wxid_cache[wxid] = info
                    self.save_wxid_cache()
                    return info
                    
            raise Exception(f"API返回错误: {response.text}")
            
        except Exception as e:
            print(f"获取小程序信息失败: {str(e)}")
            # 如果获取失败，使用wxid作为名称
            return {
                'wxid': wxid,
                'nickname': wxid,
                'principal_name': '未知开发者',
                'description': '无法获取小程序信息'
            }
        
    def update_tree(self, info):
        self.tree.insert('', 'end', values=(
            info['nickname'],
            info['principal_name'],
            info['description']
        ))
        
    def browse_output(self):
        """浏览并选择输出目录"""
        new_dir = filedialog.askdirectory(initialdir=self.output_dir)
        if new_dir:
            self.output_dir = new_dir
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, self.output_dir)
            
    def on_select(self, event):
        selected = self.tree.focus()
        if not selected:
            return
            
        item = self.tree.item(selected)
        values = item['values']
        wxid = [x for x in self.wxid_infos if x['nickname'] == values[0]][0]
        
        # 设置默认输出目录为小程序目录下的unpack子目录
        self.output_dir = os.path.join(wxid['location'], 'unpack')
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, self.output_dir)
        
        detail = f"名称: {wxid['nickname']}\n"
        detail += f"开发者: {wxid['principal_name']}\n"
        detail += f"描述: {wxid['description']}\n"
        detail += f"位置: {wxid['location']}"
        
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, detail)
        self.unpack_btn['state'] = tk.NORMAL
        
    def decrypt_file(self, wxid, wxapkg_path):
        """解密wxapkg文件"""
        try:
            salt = b'saltiest'
            iv = b'the iv: 16 bytes'
            
            with open(wxapkg_path, 'rb') as f:
                encrypted_data = f.read()
            
            if len(encrypted_data) < 1030:  # 6 + 1024 字节的最小长度要求
                raise ValueError(f"文件太小: {len(encrypted_data)} 字节")
            
            print(f"处理文件: {wxapkg_path}, 大小: {len(encrypted_data)} 字节")

            # 生成解密密钥
            dk = PBKDF2(wxid.encode(), salt, dkLen=32, count=1000)
            cipher = AES.new(dk, AES.MODE_CBC, iv)
            
            # 解密前1024字节，跳过前6个字节
            encrypted_header = encrypted_data[6:6+1024]
            header = cipher.decrypt(encrypted_header)
            
            # 处理剩余数据
            xor_key = ord(wxid[-2]) if len(wxid) >= 2 else 0x66
            body = bytearray(len(encrypted_data) - 1024 - 6)  # 移除前6字节和1024字节头部
            
            # 从第1030字节开始处理剩余数据
            for i, b in enumerate(encrypted_data[1024+6:]):
                body[i] = b ^ xor_key
            
            # 合并数据 - 保持完整的header
            decrypted = header[:1023] + bytes(body)  # 去掉header最后一个字节
            
            # 验证文件头标记
            if decrypted[0] != 0xBE or decrypted[13] != 0xED:
                print(f"文件头: {' '.join([f'{b:02x}' for b in decrypted[:16]])}")
                print(f"期望的标记: BE ... ED")
                print(f"实际的标记: {decrypted[0]:02x} ... {decrypted[13]:02x}")
                raise ValueError(f"无效的wxapkg文件标记: {decrypted[0]:02x} {decrypted[13]:02x}")
            
            print(f"解密完成: 头部大小={len(header[:1023])}, 主体大小={len(body)}, 总大小={len(decrypted)}")
            
            # 调试输出
            if b'app-config.json' in decrypted:
                print("发现app-config.json，检查其内容...")
                try:
                    start = decrypted.index(b'{')
                    end = decrypted.rindex(b'}') + 1
                    config_data = decrypted[start:end]
                    print(f"配置文件内容: {config_data.decode('utf-8')}")
                except Exception as e:
                    print(f"提取配置文件内容失败: {str(e)}")
            
            return decrypted
            
        except Exception as e:
            raise Exception(f"解密失败: {str(e)}")

    def is_game_project(self, config_data):
        """判断是否为微信小游戏项目"""
        try:
            # 确保配置文件内容完整
            start = config_data.index(b'{')
            end = config_data.rindex(b'}') + 1
            config_data = config_data[start:end]
            
            # 将二进制数据解码为字符串
            config_str = config_data.decode('utf-8')
            print(f"解析的JSON内容: {config_str}")
            
            config = json.loads(config_str)
            
            # 检查是否包含游戏相关的配置项
            is_game = (
                'deviceOrientation' in config or  # 游戏通常会设置屏幕方向
                'openDataContext' in config or    # 游戏排行榜相关
                'workers' in config or            # 游戏常用 worker
                config.get('subpackages', []) or  # 游戏通常有分包
                'plugins' in config               # 游戏可能使用插件
            )
            
            if is_game:
                print("检测到游戏特征:")
                print(f"- deviceOrientation: {'deviceOrientation' in config}")
                print(f"- openDataContext: {'openDataContext' in config}")
                print(f"- workers: {'workers' in config}")
                print(f"- subpackages: {bool(config.get('subpackages', []))}")
                print(f"- plugins: {'plugins' in config}")
            
            return is_game
            
        except Exception as e:
            print(f"解析配置文件失败: {str(e)}")
            if 'config_str' in locals():
                print(f"JSON内容: {config_str}")
            return False

    def unpack(self, decrypted_data, output_dir):
        """解包已解密数据"""
        try:
            # 解析文件头
            if len(decrypted_data) < 14:
                raise ValueError("文件数据不完整")
            
            # 读取文件头信息
            first_mark = decrypted_data[0]
            info1 = struct.unpack('>L', decrypted_data[1:5])[0]
            index_info_length = struct.unpack('>L', decrypted_data[5:9])[0]
            body_info_length = struct.unpack('>L', decrypted_data[9:13])[0]
            last_mark = decrypted_data[13]
            
            if first_mark != 0xBE or last_mark != 0xED:
                raise ValueError(f"无效的wxapkg文件标记: {first_mark:02x} {last_mark:02x}")

            # 读取文件数量
            current_pos = 14
            file_count = struct.unpack('>L', decrypted_data[current_pos:current_pos+4])[0]
            current_pos += 4
            
            print(f"文件头: first_mark={first_mark:02x}, last_mark={last_mark:02x}")
            print(f"文件数量: {file_count}")
            print(f"索引长度: {index_info_length}, 数据长度: {body_info_length}")
            
            # 解析文件索引
            files = []
            for _ in range(file_count):
                try:
                    # 读取文件名长度
                    name_len = struct.unpack('>L', decrypted_data[current_pos:current_pos+4])[0]
                    current_pos += 4
                    
                    # 读取文件名 - 添加错误处理
                    try:
                        name = decrypted_data[current_pos:current_pos+name_len].decode('utf-8')
                    except UnicodeDecodeError:
                        # 如果UTF-8解码失败，尝试其他编码或使用替代字符
                        try:
                            name = decrypted_data[current_pos:current_pos+name_len].decode('utf-8', errors='replace')
                        except:
                            name = f"unknown_file_{len(files)}"
                    current_pos += name_len
                    
                    # 读取文件偏移和大小
                    offset = struct.unpack('>L', decrypted_data[current_pos:current_pos+4])[0]
                    current_pos += 4
                    size = struct.unpack('>L', decrypted_data[current_pos:current_pos+4])[0]
                    current_pos += 4
                    
                    files.append((name, offset, size))
                    print(f"找到文件: {name}, 偏移: {offset}, 大小: {size}")
                except Exception as e:
                    print(f"解析文件索引时出错: {str(e)}")
                    current_pos += name_len + 8  # 跳过这个文件的索引
                    continue

            # 创建输出目录
            os.makedirs(output_dir, exist_ok=True)
            
            # 保存文件
            total = 0
            for name, offset, size in files:
                try:
                    # 提取文件数据
                    file_data = decrypted_data[offset:offset+size]
                    if len(file_data) != size:
                        print(f"警告: 文件 {name} 大小不匹配, 预期: {size}, 实际: {len(file_data)}")
                    
                    # 检查是否需要重命名 app-config.json
                    if name.endswith('/app-config.json') or name == 'app-config.json':
                        try:
                            print(f"检查配置文件: {name}")
                            if self.is_game_project(file_data):
                                new_name = name.replace('app-config.json', 'game.json')
                                print(f"检测到小游戏配置，将 {name} 重命名为: {new_name}")
                                name = new_name
                            else:
                                print("不是小游戏配置文件")
                        except Exception as e:
                            print(f"检查配置文件时出错: {str(e)}")
                    
                    # 规范化文件路径
                    file_path = os.path.join(output_dir, name.lstrip('/'))
                    
                    # 使用新的保存函数
                    if self.save_file_content(file_path, file_data):
                        print(f"已保存文件: {file_path}")
                        total += 1
                        self.update_progress(total/file_count)
            
                except Exception as e:
                    print(f"处理文件 {name} 时出错: {str(e)}")
                    continue
            
            return total
            
        except Exception as e:
            messagebox.showerror("解包错误", f"解包过程出错: {str(e)}")
            return 0

    def update_progress(self, value):
        """更新进度条"""
        self.progress['value'] = value * 100
        self.root.update_idletasks()

    def unpack_selected(self):
        selected = self.tree.focus()
        if not selected:
            return
        
        item = self.tree.item(selected)
        values = item['values']
        wx_info = next(x for x in self.wxid_infos if x['nickname'] == values[0])
        
        # 直接使用当前设置的输出目录
        output_dir = self.output_entry.get()
        if not output_dir:
            messagebox.showerror("错误", "请指定输出目录")
            return
            
        print(f"使用输出目录: {output_dir}")
        
        # 在后台执行解包
        def do_unpack():
            try:
                wxid = wx_info['wxid']
                wxapp_dir = wx_info['location']
                
                print(f"开始处理小程序: {wxid}")
                print(f"小程序目录: {wxapp_dir}")
                
                # 扫描所有.wxapkg文件
                pkg_files = []
                for root, dirs, files in os.walk(wxapp_dir):
                    for file in files:
                        if file.endswith('.wxapkg'):
                            pkg_files.append(os.path.join(root, file))
                
                print(f"找到 {len(pkg_files)} 个wxapkg文件")
                
                total_files = 0
                for pkg in pkg_files:
                    print(f"\n处理文件包: {pkg}")
                    decrypted = self.decrypt_file(wxid, pkg)
                    count = self.unpack(decrypted, output_dir)
                    total_files += count
                    print(f"该包解包完成，解出 {count} 个文件")
                
                if messagebox.askquestion("完成", 
                    f"成功解包{total_files}个文件\n输出目录: {output_dir}\n\n是否打开输出目录？",
                    icon='info') == 'yes':
                    # 根据操作系统打开文件夹
                    if os.name == 'nt':  # Windows
                        os.startfile(output_dir)
                    elif os.name == 'posix':  # macOS 和 Linux
                        try:
                            os.system(f'open "{output_dir}"')  # macOS
                        except:
                            os.system(f'xdg-open "{output_dir}"')  # Linux
                
            except Exception as e:
                messagebox.showerror("错误", str(e))
            finally:
                self.progress['value'] = 0
        
        threading.Thread(target=do_unpack).start()

    def minify_js(self, content):
        """压缩JS代码"""
        try:
            import jsmin
            return jsmin.jsmin(content)
        except ImportError:
            print("jsmin模块未安装，跳过JS压缩")
            return content

    def minify_json(self, content):
        """压缩JSON内容"""
        try:
            data = json.loads(content)
            return json.dumps(data, separators=(',', ':'))
        except:
            return content

    def minify_png(self, content):
        """压缩PNG图片"""
        try:
            from PIL import Image
            import io
            
            # 将二进制内容转换为图片对象
            input_buffer = io.BytesIO(content)
            image = Image.open(input_buffer)
            
            # 如果不是PNG格式，直接返回原内容
            if image.format != 'PNG':
                return content
            
            # 获取原始大小
            original_size = len(content)
            
            # 创建输出缓冲区
            output = io.BytesIO()
            
            # 保持原始模式，使用优化参数
            image.save(output, 
                      format='PNG',
                      optimize=True,
                      quality=85,  # 质量参数
                      compress_level=9)  # 最大压缩级别
            
            # 获取压缩后的内容
            compressed_content = output.getvalue()
            compressed_size = len(compressed_content)
            
            # 如果压缩后反而变大，则返回原始内容
            if compressed_size >= original_size:
                print(f"PNG压缩后变大 ({original_size} -> {compressed_size})，保持原始大小")
                return content
            
            print(f"PNG压缩成功: {original_size} -> {compressed_size} bytes ({(compressed_size/original_size*100):.1f}%)")
            return compressed_content
            
        except Exception as e:
            print(f"PNG压缩失败: {str(e)}")
            return content

    def should_compress(self, filename):
        """判断文件是否需要压缩"""
        if filename.endswith(('.js', '.json')):
            return self.compress_var.get()
        elif filename.endswith('.png'):
            return self.compress_png_var.get()
        return False

    def save_file_content(self, file_path, content):
        """保存文件内容，根据需要进行压缩"""
        try:
            if self.should_compress(file_path):
                if file_path.endswith('.js'):
                    content = self.minify_js(content.decode('utf-8')).encode('utf-8')
                elif file_path.endswith('.json'):
                    content = self.minify_json(content.decode('utf-8')).encode('utf-8')
                elif file_path.endswith('.png'):
                    content = self.minify_png(content)
            
            # 确保目录存在
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # 写入文件
            with open(file_path, 'wb') as f:
                f.write(content)
            
            return True
        except Exception as e:
            print(f"保存文件 {file_path} 时出错: {str(e)}")
            return False

if __name__ == '__main__':
    root = tk.Tk()
    app = WxapkgUnpacker(root)
    root.mainloop()