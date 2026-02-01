# Graphics cheatsheet


## ghostscript

``` shell
ps2pdf -dPDFSETTINGS=/ebook <orig_pdf> <new_pdf> # shrink size of a pdf
```


## ImageMagick

convert a specific page of a PDF into eg. PNG

``` shell
convert 'file.pdf[0]' \
    -density 600 \
    -background white \
    -alpha remove \
    -resize 100% \
    -compress zip +adjoin
    /tmp/file.png
```

ImageMagick policy blocking action with PDF files.

``` shell
convert: attempt to perform an operation not allowed by the security policy `PDF' @ error/constitute.c/IsCoderAuthoriz
ed/422.
```

Update `polixy.xml`.

``` shell
xmllint --xpath '/policymap/policy[@pattern="PDF"]' /etc/ImageMagick-7/policy.xml
<policy xmlns="" domain="coder" rights="read | write" pattern="PDF"/>
```


## Printing


### CUPS

SUSE has an awesome reading about
[CUPS](https://en.opensuse.org/SDB:CUPS_in_a_Nutshell#The_Filter_.28includes_the_Driver.29).

``` shell
cupsd -t                     # test configuration
cupsctl --[no-]debug-logging # enable/disable debug logging
```

``` shell
lpstat -p -d              # list printers and default one
lpoptions -d <printer>    # set default printer
lpoptions -l -p <printer> # list printer options

lpstat -l -e | grep <printer> # show connection to a printer
```

``` shell
lpstat -o <printer>    # list jobs on printer
lprm -P <printer> <id> # kill job on printer

grep 'Printer' /sys/bus/usb/devices/*/* 2>/dev/null # list usb printers
udevadm info -p <sysfs_path>                        # show properties of usb device
grep -rH '' /sys/bus/usb/devices/*/ieee1284_id 2>/dev/null # IEEE 1284 info
```
See http://www.undocprint.org/formats/communication_protocols/ieee_1284
See https://www.cups.org/doc/options.html

``` shell
lp [-d <printer>] <file>   # print a file
lpr [-P <printer>] <file>  # print a file
```

``` shell
# limits
man cupsd.conf | egrep -A 1 'MaxJobs(PerPrinter)* number' | fmt -w80
       MaxJobs number
            Specifies the maximum number of simultaneous jobs that are allowed.
            Set to "0" to allow an unlimited number of jobs.  The default is
            "500".
--
       MaxJobsPerPrinter number
            Specifies the maximum number of simultaneous jobs that are allowed
            per printer.  The default is "0" which allows up to MaxJobs jobs
            per printer.
```

Adding a printer via CLI:

``` shell
$ systemctl is-active cups
active

# listing supported uris
$ lpinfo -v
network ipps
network lpd
network https
network ipp
network http
network socket
network smb

# listing supported models
$ lpinfo -m
Postscript-level1.ppd.gz Generic PostScript level 1 Printer Foomatic/Postscript (recommended)
Postscript-level2.ppd.gz Generic PostScript level 2 Printer Foomatic/Postscript (recommended)
Postscript.ppd.gz Postscript Generic postscript printer
raw Raw Queue
everywhere IPP Everywhere
```

CUPS does convertion via filters; an example:

``` shell
$ grep -m1 -P '^<.*Printer \w+>$' /etc/cups/printers.conf
<DefaultPrinter hp>

$ grep -P '(cupsFilter|PCFileName)' /etc/cups/ppd/hp.ppd
*cupsFilter: "application/vnd.cups-postscript 0 hpps"
*PCFileName: "HPCM3530.PPD"
```

A different PPD:

``` shell
$ grep -iP '(DeviceID|JCLTo|NickName|PCFileName|filter)' CM353PDF.PPD
*% PDF mode, using CUPS with the OpenPrinting CUPS Filters package
*PCFileName:    "CM353PDF.PPD"
*ShortNickName: "HP Color LaserJet CM3530 MFP"
*NickName:      "HP Color LaserJet CM3530 MFP PDF"
*1284DeviceID: "MFG:Hewlett-Packard;CMD:PJL,BIDI-ECP,PCLXL,PCL,PDF,PJL,POSTSCRIPT;MDL:HP Color LaserJet CM3530 MFP;CLS:PRINTER;DES:Hewlett-Packard Color LaserJet CM3530 MFP;DRV:DPDF,R0,M0;"
*JCLToPDFInterpreter: "@PJL ENTER LANGUAGE = PDF <0A>"
*cupsFilter: "application/vnd.cups-pdf 0 -"
*cupsFilter2: "application/pdf application/vnd.cups-pdf 0 pdftopdf"
```


#### CUPS: tips

- https://access.redhat.com/solutions/305283


#### CUPS: troubleshooting

When a printer in unreachable, one can see the following

```
E [05/Jun/2024:13:50:46 -0400] [Job 1026332] The printer is not responding.
E [05/Jun/2024:13:53:26 -0400] [Job 1026332] The printer is not responding.
```

However, to correlate the printer which "is not responding" in
historical data, that is, how to find out which printer was not
reachable while it is reachable now and the jobs are already all
printed, the historical logs are needed because the printer name for
the job is *only* logged when such a job is created:

``` shell
I [26/Jun/2024:18:08:04 +0200] [Job 36] Queued on "testovic" by "root".
...
D [26/Jun/2024:18:08:04 +0200] [Job 36] Sending job to queue tagged as raw...
D [26/Jun/2024:18:08:04 +0200] [Job 36] job-sheets=none,none
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[0]="testovic"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[1]="36"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[2]="root"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[3]="fstab"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[4]="1"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[5]="finishings=3 number-up=1 print-color-mode=monochrome job-uuid=urn:uuid:5d24d8bc-ea58-3dd1-423e-537915e2c4e6 job-originating-host-name=localhost date-time-at-creation= date-time-at-processing
= time-at-creation=1719418084 time-at-processing=1719418084 document-name-supplied=fstab"
D [26/Jun/2024:18:08:04 +0200] [Job 36] argv[6]="/var/spool/cups/d00036-001"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[0]="CUPS_CACHEDIR=/var/cache/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[1]="CUPS_DATADIR=/usr/share/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[2]="CUPS_DOCROOT=/usr/share/cups/doc-root"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[3]="CUPS_REQUESTROOT=/var/spool/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[4]="CUPS_SERVERBIN=/usr/lib/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[5]="CUPS_SERVERROOT=/etc/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[6]="CUPS_STATEDIR=/run/cups"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[7]="HOME=/var/spool/cups/tmp"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[8]="PATH=/usr/lib/cups/filter:/usr/bin:/usr/sbin:/bin:/usr/bin"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[9]="SERVER_ADMIN=root@t14s"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[10]="SOFTWARE=CUPS/2.4.10"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[11]="TMPDIR=/var/spool/cups/tmp"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[12]="USER=root"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[13]="CUPS_MAX_MESSAGE=2047"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[14]="CUPS_SERVER=/run/cups/cups.sock"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[15]="CUPS_ENCRYPTION=IfRequested"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[16]="IPP_PORT=631"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[17]="CHARSET=utf-8"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[18]="LANG=en_US.UTF-8"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[19]="PPD=/etc/cups/ppd/testovic.ppd"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[20]="CONTENT_TYPE=text/plain"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[21]="DEVICE_URI=socket://127.0.0.1:5170"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[22]="PRINTER_INFO=testovic"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[23]="PRINTER_LOCATION=test room"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[24]="PRINTER=testovic"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[25]="PRINTER_STATE_REASONS=none"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[26]="CUPS_FILETYPE=document"
D [26/Jun/2024:18:08:04 +0200] [Job 36] envp[27]="AUTH_I****"
```

That is, without old job data or old logs where one can see creation
of a job, it is impossible to know what printer was not reachable.

If the old data exist, one might get it from *control file*:

``` shell
$ strings /var/spool/cups/*36 | grep '^ipp'
ipp://t14s/printers/testovic!
```

CUPS files decribes: for a job it creates in spool directory at least two files,
at least one data file - eg. `d123456-001` (multidocument jobs could have more
data files with same `d<job id>` prefix) - and a control file - eg. `c123456`.
`testipp` which is not built by default but with `make unittests` could be used
to dissect a control file, an example taken from
[stackoverflow.com](https://stackoverflow.com/questions/53688075/how-to).

``` shell
$ ./testipp /var/spool/cups/c00089

 operation-attributes-tag:

     attributes-charset (charset): utf-8
     attributes-natural-language (naturalLanguage): en-us

 job-attributes-tag:

     printer-uri (uri): ipp://localhost:631/printers/hp
     job-originating-user-name (nameWithoutLanguage): kurtpfeifle
     job-name (nameWithoutLanguage): hosts
     copies (integer): 1
     finishings (enum): none
     job-cancel-after (integer): 10800
     job-hold-until (keyword): no-hold
     job-priority (integer): 50
     job-sheets (1setOf nameWithoutLanguage): none,none
     number-up (integer): 1
     job-uuid (uri): urn:uuid:ca854775-f721-34a5-57e0-b38b8fb0f4c8
     job-originating-host-name (nameWithoutLanguage): localhost
     time-at-creation (integer): 1472022731
     time-at-processing (integer): 1472022731
     time-at-completed (integer): 1472022732
     job-id (integer): 89
     job-state (enum): completed
     job-state-reasons (keyword): processing-to-stop-point
     job-media-sheets-completed (integer): 0
     job-printer-uri (uri): ipp://host13.local:631/printers/hp
     job-k-octets (integer): 1
     document-format (mimeMediaType): text/plain
     job-printer-state-message (textWithoutLanguage): Printing page 1, 4% complete.
     job-printer-state-reasons (keyword): none
```

CUPS can cancel "stuck" jobs, ie. those expiring *MaxJobTime*

``` shell
$ lpstat -o testovic
$ grep -P 'Job 39.*Canceling stuck' /var/log/cups/error_log
I [27/Jun/2024:16:04:02 +0200] [Job 39] Canceling stuck job after 120 seconds.

$ ./cups-2.4.7/cups/testipp /var/spool/cups/c00039 | grep 'job-state '
    job-state (enum): canceled

# compare succesful jobs with all jobs but not-completed

$ grep -F -x -v -f <(lpstat -W successful -o testovic) \
    <<< "$(grep -F -x -v -f <(lpstat -W not-completed -o testovic) <(lpstat -W all -o testovic))"
testovic-38             root              2048   Thu 27 Jun 2024 03:47:37 PM CEST
testovic-39             root              2048   Thu 27 Jun 2024 04:02:01 PM CEST

$ lp -i 39 -H restart

$ ps auxww | grep -P '[s]ocket.*\b39\b'
lp         33000  0.0  0.0  14896  6908 ?        S    16:06   0:00 socket://127.0.0.1:5170 39 root fstab 1 finishings=3 number-up=1 print-color-mode=monochrome job-uuid=urn:uuid:23f8c77f-76f3-3a77-5e2c-2e447740790f job-originating-host-name=localhost date-time-at-completed= date-time-at-creation= date-time-at-processing= time-at-completed=1719497042 time-at-creation=1719496921 time-at-processing=1719497167 document-name-supplied=fstab /var/spool/cups/d00039-001

$ lpstat -o testovic
testovic-39             root              2048   Thu 27 Jun 2024 04:02:01 PM CEST
```


## scribus

Fonts, dictionaries and hyphenations can be "imported" into Scribus via: Windows - Resource Manager. See:

``` shell
$ ls -1 .local/share/scribus/{dicts/{hyph,spell}/,downloads,fonts}
.local/share/scribus/dicts/hyph/:
hyph_cs_CZ.dic
README_cs.txt

.local/share/scribus/dicts/spell/:
cs_CZ.aff
cs_CZ.dic

.local/share/scribus/downloads:
cs_CZ.aff
cs_CZ.dic
hyph_cs_CZ.dic
hyph_pl_PL.dic
pl_PL.aff
pl_PL.dic
README_cs.txt
README_pl.txt
scribus_fonts.xml
scribus_fonts.xml.sha256
scribus_help.xml
scribus_help.xml.sha256
scribus_hyph_dicts.xml
scribus_hyph_dicts.xml.sha256
scribus_palettes.xml
scribus_palettes.xml.sha256
scribus_spell_dicts.xml
scribus_spell_dicts.xml.sha256

.local/share/scribus/fonts:
```

Hm, Resource Manager could not download spellcheck dicts and hyphenation data, so I did:

``` shell
$ curl -Ls 'https://download.documentfoundation.org/libreoffice/src/24.8.1/libreoffice-dictionaries-24.8.1.2.tar.xz?idx=2' | \
    bsdtar --strip-components 3 -xf - -C ~/.local/share/scribus/dicts/spell 'libreoffice*/cs_CZ/cs_CZ*'
$ curl -Ls 'https://download.documentfoundation.org/libreoffice/src/24.8.1/libreoffice-dictionaries-24.8.1.2.tar.xz?idx=2' | \
    bsdtar --strip-components 3 -xf - -C ~/.local/share/scribus/dicts/hyph 'libreoffice*/cs_CZ/hyph_cs_CZ*'
```

Scribus uses unicode character U+00AD (soft hyphen) as a hyphenation
character in its _sla_ format.

``` shell
$ tac /tmp/out.sla | grep -m1 -Po 'ITEXT.*CH="\K[^"]+' | xxd -a
00000000: 5465 c2ad 7a65 0a                        Te..ze.
```

However, if you explictly insert a soft hyphen (Insert - Character -
Soft Hyphen), it doubles that unicode character.

``` shell
$ tac /tmp/out.sla | grep -m1 -Po 'ITEXT.*CH="\K[^"]+'
Te­­ze

s tac /tmp/out.sla | grep -m1 -Po 'ITEXT.*CH="\K[^"]+' | xxd -a
00000000: 5465 c2ad c2ad 7a65 0a                   Te....ze.
```

So, this might help if one prefers to hyphenate the text herself via
Scribus python API, for example.

To view a PDF inside Scribus, ie. a PDF image, one needs 'PostScript
Interpreter'; that is, _ghostscript_: see, File -> Preferences ->
External Tools.

Similarly, to view printed PDF, one needs 'PDF Viewer',
eg. `SumatraPDF.exe` on Windows: again, see External Tools in
Preferences.


### Scribus: styles

Language of a style in Scribus seem to work this way:

- in the general Preferences, there's 'Document Setup - Language':
  this influences document language of the future documents, that is,
  of documents to be created. That is: if 'French' is in 'Preferences -
  Document Setup - Language', then after new document creation, the
  'Default Paragraph Style' would use 'Default Character Style'
  'French' language.
  
- once a document is opened, its text language by default is
  determined by the setting of the document creation; that is, even if
  you update 'Document Setup' language, the styles would still have
  the original language value; the only way to influence default
  language of a newly created text frame, is to update existing
  'Default Character Style' language


## TeX

Terminology as I understand it sofar (that is, it might be inappropriate):

- TeX: typesetting (low-level - instructions - or primitives ??? -
  working with "boxes", internally, everything is a box: a letter,
  word, line, paragraph...)  system, or programming language, by
  Donald Knuth
  
- TeX engines: adaptations/modifications of TeX (pdfTeX, XeTeX,
  LuaTeX...); apart from LuaTex, they do not affect the language
  itself, mostly handling input/output files, etc...

- TeX formats: collection of TeX commands, macros (eg. Plain TeX -
  from Knuth himself, LaTeX, ConTeXt - but not only that) and programs
  that load large macros collections into format files (predumped
  memory images of TeX) before calling the actual "`tex`" engine

- ConTeXt: macros, a format, a collection of tools/scripts, an
  interface; that is, it is more an eco-system; it differs from LaTeX
  in philosofy: unlike LaTeX, it does not limit flexibility due to
  simplifying the use of TeX or isolating the user from typesetting
  details, that is, it gives the user absolute and complete control
  over typesetting.


### ConTeXt

``` shell
$ mkdir -p ~/.local/stow/context2025
$ ln -s context2025 ~/.local/stow/context
$ cd $_
$ curl -Ls https://lmtx.pragma-ade.com/install-lmtx/context-linux-64.zip | bsdtar -xvf -
x bin/
x bin/mtxrun
x bin/mtx-install.lua
x bin/mtxrun.lua
x install.sh
x installation.pdf

$ bash ./install.sh
```


### Texlive

idea taken from [Void
Linux](https://github.com/void-linux/void-packages/blob/master/srcpkgs/texlive2021-bin/template),
some tips in Void Linux
[texlive](https://docs.voidlinux.org/config/texlive.html)
documentation

``` shell
zypper in cairo libpixman-1-0 libgraphite2-3 gd libpoppler110 libsigsegv2 \
  libzzip-0-13 libpng libjpeg-turbo freetype icu libharfbuzz0 wget perl ghostscript xz
cat > /etc/profile.d/texlive.sh <<EOF
#location of the TeXLive binaries
export PATH=$PATH:/opt/texlive/<version>/bin/x86_64-linux
EOF

mkdir -p /opt/texlive<version>-installer
curl -Ls https://mirror.ctan.org/systems/texlive/tlnet/install-tl-unx.tar.gz | \
  bsdtar --strip-components=1 -xvf - -C /opt/texlive<version>-installer
cat > /opt/texlive<version>-installer/local.profile <<EOF
TEXDIR ../texlive/2021
TEXMFCONFIG ~/.texlive2021/texmf-config
TEXMFHOME ~/texmf
TEXMFLOCAL ../texlive/texmf-local
TEXMFSYSCONFIG ../texlive/2021/texmf-config
TEXMFSYSVAR ../texlive/2021/texmf-var
TEXMFVAR ~/.texlive2021/texmf-var
selected_scheme scheme-small
EOF
cd /opt/textlive<version>-install && ./install-tl -profile local.profile

. /etc/profile.d/texlive.sh
tlmgr paper a4 # change global default paper size
```

putting pages from two documents side by side

``` shell
# pdfseparate is from poppler-tools

pdfseparate <pdf_file1> temp-%04d-file1.pdf
pdfseparate <pdf_file2> temp-%04d-file2.pdf
pdfjam temp-*-*.pdf --nup 2x1 --landscape --outfile <out_file>
```

And, for example, putting A5 on A4 landscape (that is, two A5 same
pages on on sheet).

``` shell
$ pdfseparate -f 1 -l 2 input.pdf page%d.pdf
$ pdfjam --nup 2x1 --paper a4paper --landscape --outfile sheet1.pdf page1.pdf page1.pdf 
$ pdfjam --nup 2x1 --paper a4paper --landscape --outfile sheet2.pdf page2.pdf page2.pdf 
$ pdfunite sheet1.pdf sheet2.pdf final_output.pdf
```

