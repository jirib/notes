# Python

## Debugging

### pdb

```python
(Pdb) l 110,113
110  ->         if IMPORT_PAGE_EXTRACTOR: # in self.site.config:
111                 content = IMPORT_PAGE_EXTRACTOR(node)
112             else:
113                 content = node.prettify()

(Pdb) p bool(IMPORT_PAGE_EXTRACTOR)
True

(Pdb) p IMPORT_PAGE_EXTRACTOR
<function CommandImportPage._import_page.<locals>.<lambda> at 0x7f093b64ab60>

(Pdb) import inspect
(Pdb) p inspect.getsource(IMPORT_PAGE_EXTRACTOR)
'        IMPORT_PAGE_EXTRACTOR = lambda node: BeautifulSoup(node.decode_contents(), "html.parser").prettify()\n'

(Pdb) !IMPORT_PAGE_EXTRACTOR = None
(Pdb) p bool(IMPORT_PAGE_EXTRACTOR)
False

(pdb) n
(Pdb) l 110,113
110             if IMPORT_PAGE_EXTRACTOR: # in self.site.config:
111                 content = IMPORT_PAGE_EXTRACTOR(node)
112             else:
113  ->             content = node.prettify()
```

So, here, an example how to make a lamba-based variable `None`; that
is, change the code flow in the condition.

Now, breakpoints:

```python
(Pdb) l 69
 64         doc_usage = "[options] page_url [page_url,...]"
 65         doc_purpose = "import arbitrary web pages"
 66
 67         def _execute(self, options, args):
 68             import pdb;pdb.set_trace()
 69  ->         """Import a Page."""
 70             if BeautifulSoup is None:
 71                 utils.req_missing(['bs4'], 'use the import_page plugin')
 72
 73             urls = []
 74             selector = None

(Pdb) l 86,90
 86             if not urls:
 87                 LOGGER.error(f'No page URL or file path provided.')
 88
 89             for url in args:
 90                 self._import_page(url, selector, extractor)

(Pdb) b 86
Breakpoint 1 at /home/jiri/.nikola/plugins/import_page/import_page.py:86

(Pdb) b
Num Type         Disp Enb   Where
1   breakpoint   keep yes   at /home/jiri/.nikola/plugins/import_page/import_page.py:86

(Pdb) c
> /home/jiri/.nikola/plugins/import_page/import_page.py(86)_execute()
-> if not urls:

(Pdb) l 86
 81                 elif arg == "-e" and args:
 82                     extractor = args.pop(0)
 83                 else:
 84                     urls.append(arg)  # Assume it's a page URL
 85
 86 B->         if not urls:
 87                 LOGGER.error(f'No page URL or file path provided.')
 88
 89             for url in args:
 90                 self._import_page(url, selector, extractor)
 91
```

## IDE


### Emacs

`debugpy` is an implementation of the Debug Adapter Protocol for
Python 3; DAP is an abstraction between IDEs and specific debug
adapters (like _debugpy_ for Python).

LSPs:

- [basepyright](https://docs.basedpyright.com/latest/installation/ides/) / [lsp-bridge](https://github.com/manateelazycat/lsp-bridge)
- python-lsp-server
  [`python-lsp-server`](https://github.com/python-lsp/python-lsp-server)
  is on of the possibilities.

```shell
# ensure you have pipx installed
$ pipx ensurepath
$ pipx install python-lsp-server
$ pipx runpip python-lsp-server install "python-lsp-server[all]"

$ which pylsp
/home/jiri/.local/bin/pylsp

$ pylsp --version
pylsp v1.12.2
```

The next step is to have
[`lsp-mode`](https://emacs-lsp.github.io/lsp-mode/page/installation/)
in Emacs; but that needs Emacs
[MELPA](https://stable.melpa.org/#/getting-started) repo:

```shell
# I preferred XDG structure
#   below escaped back-ticks
(require 'package)
(add-to-list 'package-archives '("melpa" . "https://melpa.org/packages/") t)
;; Comment/uncomment this line to enable MELPA Stable if desired.  See \`package-archive-priorities\`
;; and \`package-pinned-packages\`. Most users will not need or want to do this.
;;(add-to-list 'package-archives '("melpa-stable" . "https://stable.melpa.org/packages/") t)
(package-initialize)
EOF
```

Open Emacs and:

```
M-x package-refresh-contents
M-x package-install lsp-mode
M-x package-install lsp-ui
M-x package-install company
```

```
M-x lsp-mode
```

```shell
$ pstree -Aal $(pgrep emacs) | fold -w80
emacs -nw
  `-pylsp /home/jiri/.local/bin/pylsp
      |-python /home/jiri/.local/pipx/venvs/python-lsp-server/lib/python3.11/sit
e-packages/jedi/inference/compiled/subprocess/__main__.py /home/jiri/.local/pipx
/venvs/python-lsp-server/lib/python3.11/site-packages 3.11.2
      `-{pylsp}
```

## Visual Studio Code (VSCode)

_VSCode_ seems to have many Python related things built-in.

Must have extensions:

- Austin VS Code (profiling)
- Ruff (linter and formatter)


### Debugging in VSCode

As example of `.vscode/launch.json` for a Python app.

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "list-indicators argument",
      "type": "debugpy",
      "request": "launch",
      "module": "wb_country_stats",
      "args": ["--list-indicators"],
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "justMyCode": true
    },
    {
      "name": "help argument",
      "type": "debugpy",
      "request": "launch",
      "module": "wb_country_stats",
      "args": ["--help"],
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "justMyCode": true
    }
  ]
}
```

For python code, it is preferred to use _module_ instead of _program_
in `.vscode/launch.json`.

## Profiling

### Austin

> Austin is a Python frame stack sampler for CPython written in pure C. Samples are
> collected by reading the CPython interpreter virtual memory space to retrieve
> information about the currently running threads along with the stack of the frames
> that are being executed. Hence, one can use Austin to easily make powerful
> statistical profilers that have minimal impact on the target application and that
> don't require any instrumentation.

> Austin generates binary output in the MOJO format. This is a compact binary
> representation of the collected data that can be processed by the `mojo2austin` tool
> that comes with the _austin-python_ package.

```shell
$ uvx --from austin-dist austin -o sssd-inspector.mojo .venv/bin/python -m sssd_inspector --log-dir /tmp/sssd --nopager >/dev/null
              _   _
 __ _ _  _ __| |_(_)_ _
/ _` | || (_-<  _| | ' \
\__,_|\_,_/__/\__|_|_||_| 4.0.0 [gcc 13.3.0]

🐍 Python version: 3.12.12
Analyzing logs: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 21/21 [00:11<00:00,  1.83file/s]

📈 Sampling Statistics

      Total duration . . . . . . 11.57s
      Average sampling rate  . . 117.56 kHz
      Error rate . . . . . . . . 131/1359793 (0.01%)
```

```shell
$ $ mojo2austin sssd-inspector.mojo sssd-inspector.austin
$ file sssd-inspector.*
sssd-inspector.austin: ASCII text, with very long lines (2728)
sssd-inspector.mojo:   data
```

To see the output, one can use, for example:

- [speedscope](https://www.speedscope.app/) - a web-based interactive flamegraph
  visualizer - and uploading converted plain-text Austin.
  data to speedscope format.

  ```shell
  $ austin2speedscope sssd-inspector.austin sssd-inspector.speedscope
  $ file sssd-inspector.speedscope
  sssd-inspector.speedscope: ASCII text, with very long lines (65536), with no line terminators
  ```

- `austin-tui` (install via `pipx`) can be used as well:

  ```shell
  $ austin-tui .venv/bin/python -m sssd_inspector --log-dir /tmp/sssd --nopager
  ```

  ```
  Austin  TUI   Wall Time Profile                                                                                                                                                                                                CPU  --% ▇████▇▇█   MEM  --M ████████   1/13
  _________   Command .venv/bin/python -m sssd_inspector --log-dir /tmp/sssd --nopager
  ⎝__⎠ ⎝__⎠   Python 3.12.12   PID 232870      PID:TID 232870:0:38da6
  Samples 162338   ⏲️   12.42s      Threshold 0%
  OWN    TOTAL    %OWN   %TOTAL  FUNCTION
  0.00s   11.88s    0.0%   95.6%  _run_module_as_main (<frozen runpy>:199:34)                                                                                                                                                                                                    │
  0.00s   11.88s    0.0%   95.6%  _run_code (<frozen runpy>:88:5)                                                                                                                                                                                                                │
  0.00s   11.86s    0.0%   95.5%  <module> (/home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/__init__.py:3:1)                                                                                                                        │
  0.00s   11.86s    0.0%   95.5%  main (/home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/cli.py:60:29)                                                                                                                               │
  0.00s   5.65s     0.0%   45.4%  process_logs (/home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/log_inspector/orchestrator.py:84:27)                                                                                                │
  0.00s   5.65s     0.0%   45.4%  as_completed (/home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/_base.py:243:31)                                                                                                                          │
  0.00s   5.65s     0.0%   45.4%  Event.wait (/home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:655:44)                                                                                                                                           │
  5.65s   5.65s    45.4%   45.4%  Condition.wait (/home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:355:17)                                                                                                                                       │
  ```

* `pprof` - a Google tool for visualization and analysis of profiling data, it has
  also a web UI.
  ```
  $ pprof -cum -text -lines sssd-inspector.pprof 2>/dev/null
  Type: Wall time
  Showing nodes accounting for 142619878μs, 98.29% of 145099851μs total
  Dropped 586 nodes (cum <= 725499μs)
      flat  flat%   sum%        cum   cum%
         0     0%     0% 131391031μs 90.55%  Thread._bootstrap /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:1032
         0     0%     0% 131390822μs 90.55%  Thread._bootstrap_inner /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:1075
         0     0%     0% 119905466μs 82.64%  Thread.run /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:1012
  66034167μs 45.51% 45.51% 66034167μs 45.51%  _worker /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/thread.py:90
         0     0% 45.51% 53871299μs 37.13%  _worker /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/thread.py:93
         0     0% 45.51% 48691091μs 33.56%  _WorkItem.run /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/thread.py:59
         0     0% 45.51% 22942246μs 15.81%  Event.wait /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:655
  19596906μs 13.51% 59.02% 19596906μs 13.51%  process_single_file /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/log_inspector/core.py:31
  12666606μs  8.73% 67.74% 17587956μs 12.12%  process_single_file /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/log_inspector/core.py:26
         0     0% 67.74% 11503496μs  7.93%  _run_code <frozen runpy>:88
         0     0% 67.74% 11503496μs  7.93%  _run_module_as_main <frozen runpy>:199
  11484762μs  7.92% 75.66% 11484762μs  7.92%  Condition.wait /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:359
         0     0% 75.66% 11484762μs  7.92%  TMonitor.run /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/_monitor.py:60
         0     0% 75.66% 11478592μs  7.91%  <module> /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/__init__.py:3
     421μs 0.00029% 75.66% 11475043μs  7.91%  main /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/cli.py:60
  11457187μs  7.90% 83.56% 11457187μs  7.90%  Condition.wait /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:355
  10231599μs  7.05% 90.61% 10231599μs  7.05%  process_single_file /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/log_inspector/core.py:30
         0     0% 90.61%  6999020μs  4.82%  process_logs /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/log_inspector/orchestrator.py:84
         0     0% 90.61%  6998242μs  4.82%  as_completed /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/_base.py:243
         0     0% 90.61%  5180208μs  3.57%  _WorkItem.run /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/thread.py:65
     114μs 7.9e-05% 90.61%  5180164μs  3.57%  main.<locals>.ui_driver /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/cli.py:57
         0     0% 90.61%  5180050μs  3.57%  Future._invoke_callbacks /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/_base.py:340
         0     0% 90.61%  5180050μs  3.57%  Future.set_result /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/_base.py:550
         0     0% 90.61%  5180050μs  3.57%  process_logs.<locals>.<lambda> /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/log_inspector/orchestrator.py:75
         0     0% 90.61%  5179836μs  3.57%  tqdm.update /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/std.py:1242
  4921246μs  3.39% 94.00%  4921246μs  3.39%  Path.open /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/pathlib.py:1013
         0     0% 94.00%  4460423μs  3.07%  ThreadPoolExecutor.submit /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/thread.py:180
         0     0% 94.00%  4460423μs  3.07%  process_logs /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/log_inspector/orchestrator.py:73
         0     0% 94.00%  4459683μs  3.07%  ThreadPoolExecutor._adjust_thread_count /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/concurrent/futures/thread.py:203
         0     0% 94.00%  4459242μs  3.07%  Thread.start /home/jiri/.local/share/mise/installs/python/3.12.12/lib/python3.12/threading.py:999
  3066009μs  2.11% 96.11%  3066009μs  2.11%  TqdmDefaultWriteLock.acquire /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/std.py:104
         0     0% 96.11%  3065624μs  2.11%  tqdm.refresh /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/std.py:1346
         0     0% 96.11%  2114112μs  1.46%  tqdm.display /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/std.py:1495
         0     0% 96.11%  2114007μs  1.46%  tqdm.refresh /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/std.py:1347
  2112504μs  1.46% 97.57%  2112504μs  1.46%  DisableOnWriteError.disable_on_exception.<locals>.inner /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/utils.py:196
         0     0% 97.57%  2112504μs  1.46%  tqdm.status_printer.<locals>.fp_write /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/std.py:452
         0     0% 97.57%  2112504μs  1.46%  tqdm.status_printer.<locals>.print_status /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/.venv/lib/python3.12/site-packages/tqdm/std.py:459
  1048357μs  0.72% 98.29%  1048357μs  0.72%  process_single_file /home/jiri/Sync/Documents/personal/src/github.com/jirib/py-sssd-inspector/src/sssd_inspector/log_inspector/core.py:28
  ```

* VSCode Austin VS Code extension, very cool


## Templating

### Jinja

`jinja-cli` is nice tools to validate Jinja templates/syntax:

```shell
# here testing overload of apache_httpd_package variable

$ printf '%s\n%s\n' '{% set _pkg = apache_httpd_package | default("apache2", true) %}' '{{- _pkg }}' | \
    jinja
apache2

# ...simulating the overload, eg. for a distro which has different package name

$ printf '%s\n%s\n' '{% set _pkg = apache_httpd_package | default("apache2", true) %}' '{{- _pkg }}' | \
    jinja -D apache_httpd_package httpd
httpd
```


## Tips and tricks


### Using Google CEL in Python

[Google
CEL](https://python-common-expression-language.readthedocs.io/en/latest)
might be a way to go, if you need a scripting in Python with a safe,
embeddable expression language.

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "common-expression-language",
#     "typing-extensions",
# ]
# ///

import cel

expr_str = "line.contains('Constraint violation') ? 'LDAP Error Flagged' : ''"
program = cel.compile(expr_str)

# Run evaluation
res = program.execute({"line": "sssd status: Constraint violation detected"})

if res:
    print(res)
```

Reading _expr_ from an internal file:

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "common-expression-language",
#     "typing-extensions",
# ]
# ///

import sys

from pathlib import Path

import cel

expr_file = Path("/tmp/test.expr")

# Read the expression from the file
try:
    with expr_file.open(mode="r", encoding="utf-8") as f:
        expr_str = f.read()
except FileNotFoundError:
    print("Expression file not found.")
    sys.exit(1)

try:
    program = cel.compile(expr_str)
except cel.CELCompileError as e:
    print(f"Failed to compile expression: {e}")
    sys.exit(1)

res = program.execute({"line": "sssd status: Constraint violation detected"})

if res:
    print(res[0])
```

```expr
// ==================================
// SSSD Error Pattern Dictionary List
// ==================================
[
  {
    "pattern": "Constraint violation",
    "message": "LDAP: Constraint violation (AD Policy restriction)"
  }
]
// ======================================================================================
// EDIT WITH CAUTION: The following code processes log lines and matches them against
// the above patterns to generate user-friendly messages. Do not modify the logic without
// understanding the context of the patterns and their corresponding messages.
// ======================================================================================
.filter(item, line.contains(item.pattern))
.map(item, item.message)
```

```shell
$ uv run test.py
LDAP: Constraint violation (AD Policy restriction)
```


## Tools


### poetry

> Python packaging and dependency management made easy

```shell
$ poetry new test_project

$ cd $_

$ poetry add pyyaml remote_pdb

$ $ ls -d .venv
.venv
$ $ cat pyproject.toml
[project]
name = "test-project"
version = "0.1.0"
description = ""
authors = [
    {name = "Jiří XXXX",email = "jiribXXXXX"}
]
readme = "README.md"
requires-python = ">=3.14"
dependencies = [
    "pyyaml (>=6.0.3,<7.0.0)",
    "remote-pdb (>=2.1.0,<3.0.0)"
]

[tool.poetry]
packages = [{include = "test_project", from = "src"}]

[build-system]
requires = ["poetry-core>=2.0.0,<3.0.0"]
build-backend = "poetry.core.masonry.api"
```

### UV

> uv is an extremely fast package and project manager written in Rust. It doesn’t
> just replace Poetry; it is designed to replace pip, pip-tools, pipx, poetry, pyenv,
> and virtualenv all in a single, lightning-fast binary.

This is a old-style manual way:

```shell
$ mkdir test_project
$ cd $_

$ python -m venv .venv
$ pip install pyyaml remote_pdb
$ pip freeze > requirements.txt

$ cat requirements.txt
PyYAML==6.0.2
remote-pdb==2.1.0
```

_UV_ way:

```shell
$ uv init test_project

$ cd $_

$ uv add pyyaml remote_pdb

$ ls -d .venv
.venv
$ $ cat pyproject.toml
[project]
name = "test-project"
version = "0.1.0"
description = "Add your description here"
readme = "README.md"
requires-python = ">=3.13"
dependencies = [
    "pyyaml>=6.0.3",
    "remote-pdb>=2.1.0",
]
```
