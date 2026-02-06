# Python development

### Python: UV and Mise

You don't need to care about a Python installer, just use `mise`...

* `mise install python@3.13 # or anything as above 'requires-python'`
* `mise use python@3.13     # or anything as above 'requires-python'`
* `mise use -g uv@latest`


### Python: Emacs integration

`debugpy` is an implementation of the Debug Adapter Protocol for
Python 3; DAP is an abstraction between IDEs and specific debug
adapters (like *debugpy* for Python).

LSPs:

- [basepyright](https://docs.basedpyright.com/latest/installation/ides/) / [lsp-bridge](https://github.com/manateelazycat/lsp-bridge)
- python-lsp-server
[`python-lsp-server`](https://github.com/python-lsp/python-lsp-server)
is on of the possibilities.


``` shell
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

``` shell
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

``` shell
$ pstree -Aal $(pgrep emacs) | fold -w80
emacs -nw
  `-pylsp /home/jiri/.local/bin/pylsp
      |-python /home/jiri/.local/pipx/venvs/python-lsp-server/lib/python3.11/sit
e-packages/jedi/inference/compiled/subprocess/__main__.py /home/jiri/.local/pipx
/venvs/python-lsp-server/lib/python3.11/site-packages 3.11.2
      `-{pylsp}
```


### Python: debugger aka pdb

``` python
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

``` python
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


### Python: project management tools

This is the simplest approach:

``` shell
$ python -m venv .venv
$ pip install pyyaml remote_pdb
$ pip freeze > requirements.txt
cat requirements.txt 
PyYAML==6.0.2
remote-pdb==2.1.0
```


### mise & uv

`mise.toml` for development setup, `pyproject.toml` for the actual
Python project.

This is good for simple projects, eg. scripts...

``` shell
$ cat mise.toml 
min_version = "2026.2.4"

[env]
_.python.venv = { path = ".venv", create = true }

[tools]
python = "3.14"
uv = "latest"

[tasks.test]
description = "Run tests"
run = "uv run pytest"

[tasks.lint]
description = "Lint the code"
run = "ruff check src/"
```

``` shell
$ cat pyproject.toml 
[project]
name = "foobar"
version = "0.0.1"
description = "Foobar project"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "requests",
]

[project.scripts]
foobar = "foobar.cli:main"

[dependency-groups]
dev = [
    "ruff",
    "pytest",
]

[tool.ruff.lint]
select = ["Q"]

[tool.ruff.lint.flake8-quotes]
inline-quotes = "double"
multiline-quotes = "double"
docstring-quotes = "double"

[tool.uv]
package = true
```

This way, you can setup development environment with `mise install`,
and use the application via `pipx`.


#### poetry

Modern way:

``` shell
$ mise use -g poetry

$ poetry new wb-country-stats

$ find wb-country-stats/
wb-country-stats/
wb-country-stats/src
wb-country-stats/src/wb_country_stats
wb-country-stats/src/wb_country_stats/__init__.py
wb-country-stats/README.md
wb-country-stats/tests
wb-country-stats/tests/__init__.py
wb-country-stats/pyproject.toml
```


#### uv


##### uv on Windows

This is a variation of [`uv`
Installation](https://github.com/astral-sh/uv#installation), I needed
that this way, because I was setting HTTP proxy for current powershell
session, my Windows have no direct access to Internet.

1. powershell
2. `Set-ExecutionPolicy RemoteSigned -scope CurrentUser`
3. `(irm https://astral.sh/uv/install.ps1) -replace '\bexit\b', '#exit removed' | iex`
4. `$env:Path = "C:\Users\user\.local\bin;$env:Path"`
5. Use a [PEP 723](https://peps.python.org/pep-0723/) comfortant
   script, see https://realpython.com/python-script-structure/
6. `uv run <python script>`
   ```
   PS C:\Users\user> uv run .\a5_to_a4.py input.pdf output.pdf
   Installed 1 package in 103ms
   Done: output.pdf
   ```

One can also run it under [`mise`](https://mise.jdx.dev/getting-started.html).

1. `winget install jdx.mise`
2. `mise use -g uv@latest`
3. `mise exec -- uv run <script>`


## Jinja templating system

`jinja-cli` is nice tools to validate Jinja templates/syntax:

``` shell
# here testing overload of apache_httpd_package variable

$ printf '%s\n%s\n' '{% set _pkg = apache_httpd_package | default("apache2", true) %}' '{{- _pkg }}' | \
    jinja
apache2

# ...simulating the overload, eg. for a distro which has different package name

$ printf '%s\n%s\n' '{% set _pkg = apache_httpd_package | default("apache2", true) %}' '{{- _pkg }}' | \
    jinja -D apache_httpd_package httpd
httpd
```
