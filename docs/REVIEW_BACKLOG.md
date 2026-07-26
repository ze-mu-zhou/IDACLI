# 代码审核问题清单（Important / Minor）

来源：2026-07-25 全仓库审核（4 个独立审核代理 + 实际运行测试验证）。
Critical 项已在本次审核后直接修复，不在此清单内。每条均带 `文件:行号`。

## 处理状态（2026-07-25 更新，测试 194/194 绿）

**Important 18 项全部处理完毕：**

- 已修复：1（SystemExit 信封）、2（格式错误保留 id）、3（非 UTF-8 stdin）、4（stdout 线程安全代理）、5（--shutdown 正确性 + SIGTERM 优雅退出）、6（daemon 请求超时）、7（pid/port/token 文件 O_EXCL+0600 加固）、8（banner 握手探活）、9（Ctrl+C 杀 worker）、10（daemon 8+ 测试、新增 test_wsl.py 19 测试）、11（patch 中途失败回滚 + 缓存 finally 失效）、12（持久缓存 DB 指纹 + force= 逃逸）、13（合并优先级文档化）、14（部分资源注册修复）、15（write_artifact 委托 ArtifactStore）、16（LICENSE + license 元数据）
- 已失效：17、18（skill 支持面调整为 Kimi Code + Codex，hermes flavor 已整体移除；claude flavor 也已移除）

**Minor 已修：** protocol CR 注释、kernel close() finally 吞异常、`available()` 改 find_spec、Windows 固定盘枚举、16 MiB 请求行上限、test_runtime 陈旧注释、`_get_connect_host` 死循环、daemon 异常记 stderr、daemon 启动失败带 stderr 尾部证据、快照名 run 唯一化 + 部分失败清理、LocalWorkerPool 文档、`_WSL_HOST` 删除、`int(text,10)` 回退（3 处）、cache `_resolve_ea` 拒绝 BADADDR、export_inventory 摘要一致化、focus 重复目标计数、`_must_succeed` 接受任意真值、README 结构清单补全 + daemon 模式文档（中英）、pyproject authors/urls/classifiers、benchmark 子进程超时、GitHub Actions CI、skill 分发测试对齐 kimi+codex。

**Minor 保留（需设计决策，未动）：** 信封 schema 合并、supervisor 改名、protocol 错误位置精度、`_resolve_ea` 三处实现合并、模块级 wrapper 生成/删除、合并 last-wins 模式、artifact 磁盘卫生、`"win"` 启发式、BADADDR 64 位回退、AIHelpers CWD 冻结、sdist/MANIFEST.in 分发策略（clone-only 还是 PyPI 需 maintainer 决策）、测试结构类 nits（mega-test 拆分、私有成员断言）。

## 自装真机验证追加发现（2026-07-25，均已修复，测试 202/202 绿）

审核清单之外，实际安装并对真实 IDA 跑端到端冒烟（`runs/selftest/`）又暴露 4 个只有真机才能发现的问题：

1. **fd 级插件噪音污染协议 stdout** — 用户机器装有 Keypatch 等插件，idalib 加载时直接往 fd 1 打横幅，绕过 Python 层 stdout 代理，`AgentSession` 解析首行即炸。修复：`__main__.py` 新增 `_guarded_protocol_stdout()`，`os.dup(1)` 保留协议通道、`os.dup2(2,1)` 把 fd1 甩给 stderr。
2. **WSLENV 误判 + wsl 子进程 GBK 崩溃** — Windows Terminal 给所有会话设 `WSLENV`（本机无 WSL），`get_daemon_dir` 误判走 `\\wsl$` UNC 崩 WinError 67；`wsl.exe` 输出 UTF-16 导致 reader 线程 `UnicodeDecodeError`。修复：`daemon.py` 前置探测 `\\wsl$` 可达性，子进程输出改 bytes 捕获后手动解码（含 `\x00` 走 utf-16-le）。
3. **daemon 在连接线程执行 IDA API** — C4 并发修复把 `execute_request` 放到连接线程，但 IDA 只在打开数据库的线程上响应，报 `RuntimeError: Function can be called from the main thread only`。修复：`_MainThreadExecutor`（queue + Event），连接线程入队等待，`serve_forever` 所在线程出队执行。
4. **相对/绝对路径 daemon 身份不一致** — `_normalize_target_path` 不做绝对化，`--shutdown runs/x.i64`（相对）找不到以绝对路径启动的 daemon。修复：非 `/mnt/` 路径一律 `Path.resolve()` 后再哈希。

---

## Important（应该修）

### 协议 / 内核 / 运行时

1. **`SystemExit` 杀死会话且无协议信封** — `runtime.py:78` 只 catch `Exception`；被执行代码中 `sys.exit()`/`exit()` 直接终结内核进程，客户端只见 EOF，无法区分"内核死亡"与"代码调用了 exit"。修法：在 `execute` 内 catch `SystemExit`，返回 `type: "SystemExit"` 错误信封。
2. **格式错误的请求丢失 id 关联** — `__main__.py:118-123`：`RequestFormatError` 经 `_startup_error` 发出，信封不带 id（JSON 已解析成功、id 可知，如 `{"id": 5, "code": 7}`）。按 id 匹配响应的客户端在调试畸形请求时丢失关联。修法：`parse_request` 把 id 附到异常上，或在错误路径 best-effort 重新解析 id。
3. **非 UTF-8 stdin 炸掉 stdio 循环** — `__main__.py:109`：文本模式迭代 stdin，一个非法字节即抛出未捕获的 `UnicodeDecodeError`，内核裸 traceback 死亡。daemon 路径已有 `errors="replace"`（`daemon.py:214-215`）但 stdio 路径没有。修法：启动时 `sys.stdin.reconfigure(errors="replace")` 或读 `sys.stdin.buffer` 逐行 decode。
4. **stdout 捕获非线程安全，可破坏协议流** — `runtime.py:75`：`redirect_stdout/stderr` 替换进程全局流；被执行代码 spawn 的线程（或 IDA 后台线程）在 `with` 块退出后会把裸文本写进协议 stdout，破坏后续所有响应的 JSONL 帧。修法：安装进程级 stdout 代理，按线程本地状态路由（捕获期入缓冲，否则入原始流）。
5. **`--shutdown` 强杀且清理逻辑有误** — `__main__.py:97-104`：无 SIGTERM handler（优雅清理全跳过）；kill 失败也删 pid/port 文件（孤儿 daemon 无法被发现）；`int(open(...).read())` 泄漏文件句柄且 `ValueError` 未捕获；PID 复用会误杀无关进程；写入 `NoDaemonError` 信封后仍返回 0。修法：daemon 安装 SIGTERM handler 走优雅路径（或协议级 shutdown 请求），确认死亡后再清理文件，出错返回非零。

### daemon / 并发 / WSL

6. **daemon 模式下所有超时被静默忽略** — `agent_bridge.py:231-236`：socket 未 `settimeout`，`request_timeout_s` 和 `timeout_s` 均不生效；daemon 挂起 = agent 永久挂起，且无子进程路径的 kill 兜底。修法：`DaemonClient` 持有 socket 引用，按读设置超时。
7. **pid/port 文件可被同机用户伪造/symlink 攻击** — `daemon.py:21,131-138,190-191` + `__main__.py:97-100`：文件名是公开路径的确定性哈希，目录在共享 `/tmp`；可预创建 port 文件指向攻击者服务器、用 symlink 让 daemon 覆写任意文件、写入任意 PID 让 `--shutdown` 代为 SIGTERM。修法：`os.open(O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)`，目录 0700，经 socket 验证对端身份。
8. **`is_daemon_running` 假阳性** — `daemon.py:152-159`：TCP connect 成功即判活。崩溃后端口被无关进程复用时，客户端会往随机服务里灌任意 Python，`--daemon` 也拒绝启动。修法：探活要求协议握手/banner。
9. **Ctrl+C 不能及时杀掉 IDA worker** — `parallel_runner.py:341-352`：worker 线程 `daemon=False` 且无中断，取消后仍跑完当前请求（默认 30s）才能退出，IDA 子进程空转。修法：`run()` 捕获 `KeyboardInterrupt`，先 close 各 worker 的 `JsonlWorkerProcess` 再 join。
10. **daemon.py 和 wsl.py 测试覆盖为零** — 风险最高、改动最新的代码完全无测试。WSL 路径转换纯函数（`wsl.py:121-138`）和 `_normalize_target_path` 可无 WSL 单测。

### 分析层 / 缓存 / 变更

11. **`patch_bytes` 应用非原子 + 失败时缓存不失效** — `mutations.py:136-142` + `ai_helpers.py:425-430`：逐字节补丁中途失败留下半截写入，且 `MutationError` 在 `mark_stale` 之前抛出，缓存继续供旧数据；rename 遇 IDA 名称净化时同样（post-check 在 DB 已改后 raise，`ai_helpers.py:382-383` 未失效）。修法：try/finally 保证任何落写后标记缓存失效；中途失败按 `old_bytes` 回滚或在文档中大声声明非原子性。
12. **持久缓存无数据库指纹** — `cache.py:243-258,266-283`：加载只校验 kind/schema/version，二进制 A 的缓存可静默加载到 B 的会话，函数/名称/xref/伪代码全错。修法：`save_persistent` 写入 DB 指纹（input path/MD5），不匹配拒绝或要求 `force=`。
13. **冲突合并顺序敏感且语义未文档化** — `conflicts.py:27-47`：同一资源先写者赢，换分支顺序结果不同，但 docstring 只说 "deterministic merge"。修法：文档明示"传入顺序即优先级"，或按分支名排序使输出顺序无关。
14. **部分资源注册** — `conflicts.py:37-45`：多字节补丁在字节 N 碰撞被排除出 `merged`，但字节 0..N-1 已占位，后续记录会与"未合并记录"冲突且报告将其列为 `"first"`。修法：先收集冲突，确认整条记录无碰撞后再注册 `by_resource`。
15. **`AIHelpers.write_artifact` 重复造轮子且更弱** — `ai_helpers.py:356-372,915-929` vs `artifacts.py`：非原子写、无 Windows 设备名防护（`CON.json` 可写）、元数据 key 不一致（`bytes` vs `size`，绝对路径 vs 相对 POSIX 路径）。修法：委托 `ArtifactStore` 或至少共享 `_safe_relative_path` 并统一元数据。

### 打包 / 文档 / skill

16. **四处声称 MIT 但无 LICENSE 文件** — `README.md:12,197`、`README_EN.md:12,197`、`skills/hermes/ida-cli/SKILL.md:6`；`pyproject.toml` 无 license 字段。未附全文的 MIT 不构成有效授权。修法：加 `LICENSE` 文件 + `license = {text = "MIT"}` + classifiers。
17. **hermes skill 文档了不存在的符号** — `skills/hermes/ida-cli/SKILL.md:179`：`from ida_cli.parallel_runner import ParallelRunner`，实际类名是 `LocalParallelRunner`（`parallel_runner.py:309`），照做的 agent 直接 ImportError。
18. **hermes flavor 半集成** — `test_skill_distribution.py:18-28` 未校验 hermes frontmatter；`docs/AI_INSTALL.md:44` 仍说 "both agent flavors"、默认路径清单漏 `~/.hermes/skills/ida-cli`；`install_skill.py:114` 描述仍写 "Codex and Claude Code"；README 未提 hermes。

## Minor（可选）

- **死代码/误导性 CR-stripping** — `protocol.py:150-152`：`json.dumps` 本就转义控制字符，CRLF 转换发生在流层，此代码注释描述的威胁它管不到。删除或改在 `sys.stdout.reconfigure(newline="\n")` 层修。
- **两套信封 schema** — `runtime.py:103-112,131-150` 手工构建执行信封（含 `module`/`frames`），`protocol.py` 的 `error_response`/`success_response` 只用于启动/解析错误，迟早漂移。合并到一处。
- **`close()` 在 finally 路径可抛异常** — `kernel.py:132-133`（`IdaLibBackend.close` 缺 `close_database` 时 raise）、`kernel.py:59-65`、`kernel.py:167-170`：会掩盖正常退出/真实启动错误。session-close 包装层应吞掉并记 stderr。
- **启动时驱动器探测可卡顿** — `kernel.py:262-271`：26 个盘符逐个 `Path.exists()`，断开连接的映射网络盘每个可阻塞数秒。用 `GetLogicalDrives`/`GetDriveTypeW`（ctypes）跳过非固定盘。
- **JSON 常量拒绝位置报告不准** — `protocol.py:191`：`source.find(constant)` 可能匹配到字符串字面量内部。
- **`available()` 检查有 import 副作用** — `kernel.py:97-102`：为回答 yes/no 完整 import `idapro` 并改 `sys.path`/`os.environ`；`importlib.util.find_spec` 即可。
- **无请求大小上限** — `__main__.py:109` 无界读行；daemon TCP 路径建议加单行上限。
- **`int(text, 0)` 拒绝前导零十进制** — `get_ea("010")` 落入名称解析报误导性错误（`ai_helpers.py:69`、`mutations.py:290`、`cache.py:400`）。ValueError 路径先试 `int(text, 10)`。
- **BADADDR 写死 64 位** — `ai_helpers.py:633-638` 无 IDA 模块时回退 `2**64-1`，32 位 IDB 错；`cache.py:388-393` 的 `_resolve_ea` 不拒绝 BADADDR；三个 `_resolve_ea` 三种校验策略，宜合并。
- **`export_inventory` 摘要自相矛盾** — `ai_helpers.py:583` 用 `string_limit=0` 构建摘要，摘要报 `"strings_sampled": 0` 而旁边的 strings artifact 是全量。
- **`focus` 以 `str(target)` 为 key** — `ai_helpers.py:548`：重复/等价目标静默互相覆盖，`"count"` 数的是唯一 key 而非请求目标。
- **`_must_success` 只认 `1`** — `mutations.py:416-419`：API 返回其他真值（如 2）会误判失败。
- **线性历史被平铺合并报冲突** — 同一 ea 在单分支序列中 rename 两次会报冲突；无 last-wins 模式。
- **模块级 wrapper 是任意子集且已漂移** — `ai_helpers.py:1104-1369` 手工重导出 ~35 个方法，漏 `propose_*`、`patch_byte`、`save`、`cached_*` 等；生成或删除。
- **artifact 无磁盘卫生** — `runs/` 无限累积；崩溃在 temp 与 `os.replace` 之间会留下 `.tmp` 孤儿。
- **`"win"` 启发式误报** — `ai_helpers.py:23` 子串匹配 `WinMain`、`window`。
- **`AIHelpers.__init__` 构造时冻结 CWD** — `ai_helpers.py:38`，模块级单例 `ai`（`ai_helpers.py:1101`）锁定 import 时的工作目录。
- **`supervisor.py` 名字误导** — 实为分片/fanout 规划，无进程监督；改名（如 `fanout.py`）或接受混淆。
- **`_get_connect_host` 死循环** — `daemon.py:42-46`：`for` 循环第一轮即 return，未用 `word`；多行 `ip route` 输出未处理。
- **快照文件泄漏/碰撞** — `parallel_runner.py:452-480` 部分失败留下前 N 份副本无人清理；`parallel_runner.py:638-641` 快照名仅由目标名+worker 序号派生，并发跑同一目标会撞名（加 run 唯一成分）。
- **daemon 静默吞异常** — `daemon.py:218` `except Exception: pass`，生产中无法调试；至少记 stderr。
- **daemon 启动失败无证据** — `agent_bridge.py:133-141` 三路 DEVNULL，失败时只有裸 "Daemon did not start"；重定向 stderr 到临时文件并附尾部。
- **`LocalWorkerPool` 命名/线程安全** — `worker_pool.py:414-508` 无锁改 `_active`/`_completed`/`_failed`，实为串行 facade；名字易诱导并发误用。
- **`daemon.py:23` 的 `_WSL_HOST` 定义后从未使用**。
- **README 项目结构清单漏 `daemon.py`/`wsl.py`** — `README.md:172-187`、`README_EN.md:172-187` 列 13 个模块，实际 16 个；daemon 模式在所有文档/skill 中完全未提及（隐形特性还是死代码，需决策）。
- **sdist 不含 `skills/`/`docs/`/`scripts/`** — PyPI 安装后无法装 skill，README 的 `docs/AI_INSTALL.md` 链接失效；要么声明 clone-only，要么 `MANIFEST.in` + package_data。
- **陈旧注释** — `tests/test_runtime.py:111` docstring 说 "protocol.py is still empty"（早已完整实现）。
- **测试小疵** — `test_agent_bridge.py:78` 断言私有 `_process.poll()`；`test_benchmarks.py:31-51` 子进程无 `timeout=`；`test_ai_helpers.py:180` 28 断言巨型测试；`test_kernel.py` mock 5 个私有函数（脆弱接缝）；`test_artifacts.py:11-13` 唯一缺 `sys.path` shim。
- **测试边界缺口** — `test_ai_helpers.py` 无 decompile 返回 None、BADADDR、hex 字符串、size-0 读等边界；`test_conflicts.py` 缺顺序交换、多资源部分注册、repeatable comment、`save_database` 冲突、不支持 kind；`test_cache.py` 缺 schema/version 不匹配、重复函数起点、`end_ea=None`、64 位边界地址。
- **无 CI** — 套件 1.5s 零依赖，一个 GitHub Actions job（Windows + Linux 跑 `python -B -m unittest discover -s tests`）即可拦住本次两个红灯。
- **`pyproject.toml` 元数据裸** — 无 authors、`[project.urls]`、classifiers。
