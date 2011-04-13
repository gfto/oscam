/* The server string in the http header */
/* The server string in the http header */
#define SERVER "webserver/1.0"
/* The protocol that gets output. Currently only 1.0 is possible as 1.1 requires many features we don't have. */
#define PROTOCOL "HTTP/1.0"
/* The RFC1123 time format which is used in http headers. */
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"
/* The realm for http digest authentication. Gets displayed to browser. */
#define AUTHREALM "Forbidden"
/* How long a nonce is valid in seconds. If it isn't valid anymore, the browser gets a "stale=true" message and must resubmit with the current nonce. */
#define AUTHNONCEVALIDSECS 15
/* The maximum amount of GET parameters the webserver will parse. */
#define MAXGETPARAMS 100
/* The refresh delay (in seconds) when stopping OSCam via http. */
#define SHUTDOWNREFRESH 30
/* Templates: Adds a variable. The variable can be used as often as wanted. */
#define TPLADD 0
/* Templates: Appends a variable or adds it if doesn't exist yet. The variable can be used as often as wanted. */
#define TPLAPPEND 1
/* Templates: Adds a variable which will be reset to "" after being used once, either through tpl_getVar or when used in a template.
   tpl_addVar/tpl_printf don't do a reset and will overwrite the appendmode with a new value. */
#define TPLADDONCE 2
/* Templates: Appends a variable or adds it if doesn't exist yet. The variable will be reset to "" after being used once. See TPLADDONCE for details. */
#define TPLAPPENDONCE 3

#define CSS "\
body {background-color: white; font-family: Arial; font-size: 11px; text-align:center}\n\
p {color: white; }\n\
h2 {color: #F7F7F7; font-family: Arial; font-size: 50px; line-height: 50px; text-align:center; margin-top:0px; margin-bottom:0px}\n\
h4 {color: #AAAAAA; font-family: Arial; font-size: 12px; line-height: 9px; text-align:center}\n\
TABLE {border-spacing:1px; border:0px; padding:0px; margin-left:auto; margin-right:auto;}\n\
TH {height:10px; border:0px; font-family: Arial; font-size: 11px; padding:5px; background-color:#CCCCCC; color:black;}\n\
TH.statuscol0 {text-align:center;width:10px;}\n\
TH.statuscol1 {text-align:center;}\n\
TH.statuscol2 {text-align:center;}\n\
TH.statuscol3 {text-align:center;}\n\
TH.statuscol4 {text-align:center;}\n\
TH.statuscol5 {text-align:center;}\n\
TH.statuscol6 {text-align:center;}\n\
TH.statuscol7 {text-align:center;}\n\
TH.statuscol8 {text-align:center;}\n\
TH.statuscol9 {text-align:center;}\n\
TH.statuscol10 {text-align:center;}\n\
TH.statuscol11 {text-align:center;}\n\
TH.statuscol12 {text-align:center;}\n\
TH.statuscol13 {text-align:center;}\n\
TH.statuscol14 {text-align:center;}\n\
TH.statuscol15 {text-align:center;}\n\
TH.statuscol16 {text-align:center;}\n\
TD {height:10px; border:0px; font-family: Arial; font-size: 11px; padding:5px; background-color:#EEEEEE; color:black;}\n\
TD.statuscol0 {text-align:center;width:10px;}\n\
TD.statuscol1 {text-align:center;}\n\
TD.statuscol2 {text-align:center;}\n\
TD.statuscol3 {text-align:center;}\n\
TD.statuscol4 {}\n\
TD.statuscol5 {text-align:center;}\n\
TD.statuscol6 {text-align:center;}\n\
TD.statuscol7 {text-align:center;}\n\
TD.statuscol8 {text-align:center;}\n\
TD.statuscol9 {}\n\
TD.statuscol10 {text-align:center;}\n\
TD.statuscol11 {text-align:center;}\n\
TD.statuscol12 {text-align:center;}\n\
TD.statuscol13 {}\n\
TD.statuscol14 {text-align:center;}\n\
TD.statuscol14 A {text-decoration: none;}\n\
TD.statuscol15 {text-align:center;}\n\
TD.statuscol16 {text-align:center;}\n\
TD.statuscol16 A {text-decoration: none;}\n\
HR {height:1px; border-width:0; color:white; background-color:#AAAAAA}\n\
TR.s TD {background-color:#e1e1ef;}\n\
TR.l TD {background-color:#e1e1ef;}\n\
TR.n TD {background-color:#e1e1ef;}\n\
TR.h TD {background-color:#e1e1ef;}\n\
TR.r TD {background-color:#fff3e7;}\n\
TR.p TD {background-color:#fdfbe1;}\n\
TR.c TD {background-color:#f1f5e6;}\n\
TR.a TD {background-color:#33ff00;}\n\
TR.online TD {background-color:#f1f5e6;}\n\
TR.expired TD {background-color:#ffe2d4;}\n\
TR.usrcfg_anticasc TD {background-color:#FEF9BF;}\n\
TR.usrcfg_cccam TD {background-color:#E6FEBF;}\n\
TR.scanusbsubhead TD {background-color:#fdfbe1;}\n\
DIV.log {border:1px dotted #AAAAAA; background-color: #FAFAFA; padding:10; font-family:\"Courier New\", monospace; color:#666666; font-size: 11px; word-wrap:break-word; text-align:left; }\n\
DIV.sidlist {border:1px dotted #AAAAAA; background-color: #fffdf5; padding:2; font-family:\"Courier New\", monospace ; color:#666666; font-size: 11px; word-wrap:break-word; text-align:left;}\n\
TABLE.menu {border-spacing:0px; border:0px; padding:0px; margin-left:auto; margin-right:auto;}\n\
TABLE.status {border-spacing:1px; border:0px; padding:0px; background-color:white; empty-cells:show;}\n\
TABLE.config {width:750px;}\n\
TABLE.invisible TD {border:0px; font-family:Arial; font-size: 12px; padding:5px; background-color:#EEEEEE;}\n\
TD.menu {font-color:wblack; background-color:white; font-family: Arial; font-size:14px; font-weight:bold;}\n\
TD.script {font-color:black; background-color:white; font-family: Arial; font-size:14px; font-weight:bold;}\n\
TD.shutdown {font-color:black; background-color:white; font-family: Arial; font-size:14px; font-weight:bold;}\n\
TD.shutdown A:hover {color: red;}\n\
TD.configmenu {font-color:black; background-color:white; font-family: Arial; font-size:11px; font-weight:bold;}\n\
textarea.bt{font-family: Arial; font-size: 12px;}\n\
textarea.editor {width:100%; height:450px;border:1px dotted #AAAAAA; background-color: #FAFAFA; padding:10; font-family:\"Courier New\", monospace; color:#666666; font-size: 11px; word-wrap:break-word; text-align:left; }\n\
input{font-family: Arial; font-size: 12px;}\n\
A:link {color: #050840;}\n\
A.debugls:link {color: white;background-color:red;}\n\
A.debugls:visited {color: white;background-color:red;}\n\
A:visited {color: #050840;}\n\
A:active {color: #050840;}\n\
A:hover {color: #ff9e5f;}\n\
DIV.message {float:right}\n\
IMG{border:0px solid;}\n\
P.blinking {text-decoration: blink; font-weight:bold; font-size:large; color:red;}\n\
a.tooltip {position: relative; text-decoration: none; cursor:default;}\n\
a.tooltip span {display: none; z-index:99;}\n\
a:hover span{display: block;position: absolute;top: 2em; left: 1em;margin: 0px;padding: 10px;color: #335500;font-weight: normal;background: #ffffdd;text-align: left;border: 1px solid #666;}\n\
H4.styleauthor:after {content:\"Eneen\";}"

#define JSCRIPT ""

#define ICMAI "data:image/x-icon;base64,\
AAABAAEAEBAAAAEACABoBQAAFgAAACgAAAAQAAAAIAAAAAEACAAAAAAAQAEAAAAAAAAAAAAAAAAA\
AAAAAADw//8A7/D/AODg4ADf8P8A0PD/AM///wDA4P8Az8/PALDw/wCQz/8AsLC/AGDP/wBgz88A\
YJD/AGCQzwBfr+8AYJCQAC9gzwAvYJAAIADfAC8AzwAvL5AAHw+wAF9QXwAfQGAAEB9vACAgIAAQ\
LzAAABAfAA8PDwAADw8AAAAPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/\
//8AICAOBgMEBiAgIAMDBg8gICAgEQ8gDgkICAgLGA8RICAgICAgBAgIBQQEBQgbICAgICAgCAYF\
CAMBAQEDCCAgICAgIAkWEwwBAAAAAAAgICAgIB4IExYIAQwAAAAAICAgICAgCRYZFBMTFBUHASAg\
ICAgIBQTExMTExMTExYgICAgIBMTEyAgGBAgICATExMgICAZHyANDwsIBQUIICAZICAgICAgICAS\
DhwgICAgICAgICAgICD/AiD/AiAgICAgICAgICAg/xog/xogICAgICAgICAgIP8CIP8CICAgICAg\
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIMHDYQDAA2UA4AcuAMADbQBAAgAAAAACAAAA\
0QKAAW4AwAF3AMABbQDgA1wA4ANpAPAHZADwB3MA+A9hAPwfYgA="

#define ICSTA "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABmJLR0QAAAAAAAD5Q7t/AAAACXBI\
WXMAAABIAAAASABGyWs+AAAACXZwQWcAAAAQAAAAEABcxq3DAAAC3UlEQVQ4y31QTWhUVxg93733\
3ffeZPIymczoZGISMRi1kh+zEAKiCxfZBrqwpS0yIhFcxH0GFBWDFEQR3NhC7cZAFxU1+JdKsQtL\
N63Q2lYRNZkkxozOm2TG+Xtz73VhRFqNB87uO+d85xBWkBoZwXd79uCb8fHOiO8PWZXKDlavt4Oo\
pKT8qxwO35xOJH5dm8+X901MAIkEAIAA4OzgIJZc1+l+9uwzN58/xIrFrSYILBjz5ohzYxzHr3ve\
pB+JfJ2KRu+nZmdx4eFD8FN9fchz7nySyaTdxcUTVCi0Qyn+VgwA0JpQrbq8VOqzlNpwlYnJpEH1\
5ossyAD4obNzJOz7Z6hWc0GE1aCENe+vj4w7X3oz8zlM1QOq8HVdXd2xYvG0VCrJOMeHyDkHbGch\
195ytHVEDzTLl+mQZR7s7in8LVpqtWGHaBNJ+bHk5/lE07Gug+gP0XKKjOFSBAeu/Ob9JBqIdtlS\
8lXFXGT9ePj4llHR43F/P4zkgI2Qpm2bW4Me4VpWu71Kb8VYPuc1HNl4KLSuxc5/zmCXDRwQAGVA\
Ta7pENJxgtUMysb8ebuPbq2vyF12tSVt3mwOADDGmKVXpT8Ec90HEhj4oEVdB5fbMr1FMXcYRBLA\
WwOCRgWEWRE4zg1hzDAH3PcMmIYSdTvgqhUM/1mZ1dm8CMS8mBHielyIu45Su/+v16QR9cJwowAY\
reQbEBFYSdwNnrJ/xHA0mr1XqYy7Wm+WWre9+xGoG4V4swe1xgKxlQIEUMAXdImdkyleZqcLBQxm\
Mj9nbXs0kPIx4xyMMdAKY5FGJGMRJGPNSMabkWyKZeM6ml7cS7/QbRtsbGoKY21tZmBu7scnlvXp\
kpTf1oSY0ZwrQ0w32A6anAYVkeFcRHvXwrnGL15dEN/3nlyjr6fv4N34jY24ODSEaaXkdsa6o0C/\
qgbl83ur952N4Z2mxP6tPDL3Or4KLV/qmMbvmTsAgNduAx7n+HHZEQAAACV0RVh0Y3JlYXRlLWRh\
dGUAMjAwOS0wOS0yOFQxMToyNzo1NC0wNDowMEqLuj0AAAAldEVYdG1vZGlmeS1kYXRlADIwMDkt\
MDUtMThUMTY6MTA6MDAtMDQ6MDAci9a9AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5\
ccllPAAAAABJRU5ErkJggg=="

#define ICDEL "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAAsTAAALEwEAmpwYAAAA\
BGdBTUEAALGeYUxB9wAAACBjSFJNAAB6JQAAgIMAAPn/AACA6AAAUggAARVYAAA6lwAAF2/XWh+Q\
AAADFklEQVR42qSRS2icVRxHz//e+30z40zSNI1NJ5M0aWpj0hCToEiRqAhWS5G2ii7ERVdioSC4\
E7pyI5SutIsufCJaFIoQRLJQKVpKwaRYA1XTF01MWpukdJLM8/vuw0VF3HvgtzmrHxw5uWPHrvGD\
Bz7u6u3uvvDRJ58uXr3xjktTnEBOQQZIAOcDOE+kVfuD/f3vbhvY9dyN8xdOm7GXDn0zvm/vw/Ha\
XdSzE8fOrZWL1/+8fURpxX+xzpPRes/A2OiHW4eHB27PL8xvNGqXTDYTt6ryKmZ9hd5NJiru6Xvj\
+2b5qemVxhNBSTkA1ntVatt0Zmxs7FBZqdr01NTRtNH8IADyXrFILjJvPTby0LGhgt2il25SWy7z\
81+N1Ys1P5QTBoeiaLJUKrVfrtWn55ZuTeTiOMm3tlKrrCOndvZTW1nFJE3aI94fKegjHd5FSdMz\
V3eVnCNXMEbPeP/ZPesOiyiiOCaXz1OrrKNEBBMZspmYlVr65tnlxs5za+7XtbqjZEMh57z+yboT\
d7w/jNYEQAARQQCTpgn1pEnTWoxSVIW7SRoi5z0uQFYLmxXPLHuFDQBCYi3NahV8QD/eqNNMU3wI\
aOgZ9H5ut/O9VRFmjf62JSP94wXVvZBKx5plSgSch6a1JB5UCAFECNA54Nxsv/NbrBYuRerLRSUv\
/JjKy+tZ7V7cHh9VwiMuQOD+kwAouZ9ZDTg/0xdCm4mFP4y6eQt5NQaanskzd+xrsRZ5ssNMhuAx\
Ev6dkgBF5z4fCr47m9WsRNr+7uV5HcAFMEDDhq++nm8e3503fdti9br84w2ggndbh9rbXikUYsgJ\
M5YTqedKCGA9BAJZBUsN//Yv99Iro3lzXAhoQANqc6FwoO/pCdM22Iu0xCFj5FRPTtGVVXRmFaLA\
C0QaZjfsfnHhgU6tDuZFKIigqkm6mB0doWP/Xih1+Yb19dQHEh+wIRADERADAa7/VncnuxTDPRp6\
NOhHrb2WeLevZXtP8YezF08vlCtf1FNPNfVUUo8SRaQEEUGL0IDvanC+AmEDkBAC/4e/BwACT2zM\
WyQBIAAAAABJRU5ErkJggg=="

#define ICEDI "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAChUlEQVQ4jY2SW0hTcRzHv+dsO5ed\
aa65jm5uYx60UVBIRCY+9BZ0EUFDNLogLbpYD/UQRBQRQQ9BRfnQQxFBUKFCSiQ9hGSaUuCNJEPL\
W5Fzw02P7mzn8u9lTdSFfZ9/n8//++P3N2GdnBUE3PJ6X50URb+bpj+8X1xcD1lORc1hvD1Y8eAu\
QB7b7eSdJA11BgLOzQzzfwL9a2Pp4PdvpO3KTXIbIA8FgTS7XKRPkvZRqRn6X/Dn52dAJabavCO1\
2HnUicqRGcAp4lcohKlotORvB1Mm+HTNTgSP7Hoa/dm7O6GEoI0/gUUbgPtyO4iiTbz51FPVo6oA\
AGo1nC2wiA1e3Rub6m9XFoYBQ4GmzoG1+qDKXxDf8iwg7Tg+gsRi5hWGWk6widkfrYnYIMzMJqjJ\
EPisbdDVBYgbmfNVBw6l4TWCGw1l8OYzr2Phj4yZ90FLzoITimGQJKyW+e57Ldr9/vGVD6ZXcDtz\
MN1VXx8Z7X5kGAosQhGS8jAYoQj60jCZX4hmF9aG5NWN0w1KSyQYmnRdNxKwOsqhKZPgsrZDT4bg\
yCbVZQ3hNfAKQaHPCY0WCtiia9BYEQyTB8OQsYFXmi80hlt+R4xM/LLA780XGHsOaNqAKbccpuJz\
YFnIQ2NL1XdezGWEV8TndW2tqdxDYmNtJDHTRUhy9GV4ujc340fJlAKPZz9vtZECV15rZKLTfeni\
KbCcDR6PF36/H6IowuFwwG63g2XZNEfV1dUhGAz6Ozo6jtE0bS6UpAFV1a08x9p4nuNTc3EAcYqi\
CIB5iqLmOI6bbGpqGjUrioJwOJwVCAT6AOTouu5iLCaLrms2WZZJSmADIAPQkDq9oiiReDyOP4iW\
/fvrVslmAAAAAElFTkSuQmCC"

#define ICENT "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJ\
bWFnZVJlYWR5ccllPAAAAjlJREFUeNqUU99LFFEU/u7MnXHujtouJWKwbbD9MIhyoexJGXwoIhR6\
iF76A4KgJwMfliAQRJKeeqrXHgp6MqhMpTVfKoxsi/Qh2wpZUmS00FbdOzOeO625bbLYhQ9mzpzv\
O985Zy6rv/54UHCtMwgC7PQwxlCQ/qOYMLq4Ivd2tcLzfWg7IPsEXdOQHnzdqWpyScTdFkf3s2/g\
pMCqkJVHSQoDp/dB8UwqSQIBYpaBw3tqoTNlr4oAKXgEla94oYMiKToJi5DA/5x1n8FTDvzS8Kam\
PpLFfy2wMKYDmkng4XtzsgmFwAbzDPDNRDtSi6CSzH6TGbexMjkAmXsAzg18HWdIN57DtcbhLYFI\
RNCEKwbANCoq4L7qh7E0ioPtHdDNGlqFxNWZLNwl+7a2uX5LWLCsmr8gKCZsgYW3d7C/5RR0EcN0\
ZgTTLzJoOJLCqgyubDkQgv6FoKx3ZYBDp/aLHiNyNJzP3Pxi+L3ZqoOUHq2+5FrTOWH7iUsZYM2d\
g8452s5fhEYkz/0Oj3bKDb36//fyZhwtjgNDGPg1n4dhkmnPx5eZWeQXCg9ZXff9MRapby9SUHWg\
VrmuZuvZyDZdQjzVhmjiEBZnc8hmnv4RHip2POm7ce+yauAAYVdl5Uzv3oljqaOIxZNwf6zi/dgQ\
nHT+RFmK++Fua44l+obLLoqGlUBgwr6ATz/t5yZbdlR8jTeMnOl51zN+6/gbgy6MSV2PypM4a09W\
vTtJQrT0rEb/ebukDQEGABzNvVc4pYJ1AAAAAElFTkSuQmCC"

#define ICREF "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAAA4AAAAQCAYAAAAmlE46AAAABHNCSVQICAgIfAhkiAAAABl0RVh0\
U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAALFSURBVCiRZZFLaFx1FMZ/59x7M5OZSWJq\
88DYpAabBkGNLVLrKIIbxQe0+MBaZQoFERG3VtRlF0UqghHBjXONZCGCUgQRIUWdSZVWSzfWpq+Y\
ttZMm0yaTud15/6Piwwo9Vsevt/3wXfEzAAohnKHet5+4BEXx/2quiLKybjlJoGvsjmL2j4BDoqZ\
UQxlh6pOD24cCnoHBv1EaoSWy1CvXKN04ffKtdJcZM72ZHN2aHZKPjTjRSnkGVPP+3Xz1nsyyXRA\
HCUJ0qOIP4z4tyPaQ7N2lZM/vlNt1sonEumBrY3qYk1mP9MP+jYMvR4Enl6evyAudiB+nFm3sXrb\
2OOZnsHHRLxekDR/zx2wW4d3y/FvnlqR2Slv0Q/8/qgZmTlXB94CpoAJ9eT9noFtm+584GDKC7pA\
u3DxKke/vLesZnZLqxk5c+5bYBn4Ppuz5WzOZra/5CbKf/389rGvH7W4VaNV/QnWxjQ1M3XOzQGn\
AAd4tFUMJa0qr449uM/5iQ34yfsAATAp5EkD1Wyu/Zd/IQUOAU8GnX1NETVEDSCqXl6RQsgSxjr+\
r++A3UB8010AzxcItr3wB6JpwHH17Hvu7NHJc87xXDZn129OK4ayGZjx1xKUVu0IzqU4/cukAvv/\
CxVDuQv4YtMEz3QkeTdqSJ+ulXv4qYfoyGxh4olpUt2DHx35XH8ohnJ3m90VJGgsLjDZinSXerok\
xZDK/c8eSy8v5G396Bsi2oWLFlg6/7FdOjVTq19f6BBVHzA/8EVEXKPW2CfFkBvd/Vt0tfTbuc7u\
oZHxhw+kg84RLJrHtc4T18/QuDFPVLuEiM+ZE6fLzrlxKeSpqDK9/WV7pRjK86J80r1+1OsfHs8k\
Mz14skq98iflxVJUunilac6ezubssBTyfArszebMtYdIADs9X18zs3EXW696egU47GL3ZjZnFwH+\
AYRRPIe3vIMRAAAAAElFTkSuQmCC"

#define ICKIL "data:image/png;base64,\
R0lGODlhEAAQANUhAP///yk0QKGqtHF6hWBsdsopAJMAAP/M/8vS1+Lm6f9MDP+DIP8pAP8zAP9s\
FK64w9zf76Ors8nQ1evs8err8PLy/Ozv+4SMlOvw+6GqsoOJkfPy/NDT3GdweP/+/tHU3Wdvd///\
/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAACEALAAAAAAQABAAAAaHwJBw\
SBwSBEXiYDkgACSBZGgAwECcCEG0SE0IsNpk9wvIBi5cgDdAiGgfHaU6HAoEPo/tdK4HTDYAAEJj\
Wx4FBYGHgxZfBEIFBweHkQVTVwAZAQAGCwuRnQZTYAEUmw6nDqEhoxwVAAUKsQqVow8PrwcMDQ0M\
kgJmGiCaBroGBryhdknGQsxBADs="

#define ICDIS "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAAsTAAALEwEAmpwYAAAA\
BGdBTUEAALGOfPtRkwAAACBjSFJNAAB6JQAAgIMAAPn/AACA6QAAdTAAAOpgAAA6mAAAF2+SX8VG\
AAADAUlEQVR42mJkAILW1taU////FzIxMUkD6Rt///7trqurW8uABJqampwYGRkrWVhYTP/9+/cO\
qGbm1q1bewACiBkoEcvMzDyfm5tbVExMjIOfn1/mz58/YTY2Nt/3799/FKS5vr4+mouLa4WOjo66\
np4eh4CAgOD3799dZGVlvwEEEAvQVpDNDBwcHAxARQxAAxh4eHgY7t+/3wk0/AfQphdsbGwLjYyM\
mB0dHRlAaj98+MAAdAXDhQsXkgACiAVomzRI8MePHwxfv35lALqGgZeXl0FRUZHhwYMHE4Hif/X1\
9ZmBLgJrBgGgC8AWAfnCAAHE8u3bt9NATd5AGu5fYDiAFSkoKIDYzLq6unDNIPDz50+GV69eMfz+\
/fsGQACxAImOT58+OfHx8XEC/QVWCAwsMA1yCcgmoBqws4WFhcGGHz16lOH69ev/gQZNAAgg5hMn\
TjwyMDB48OvXL39gODCB/AbCMIOAoQ62FebN48ePMxw+fJjhy5cvFR0dHbMBAogZJHn69OnL2tra\
14AKvIEByQYyAKQZGQMDk+HWrVsg2/+8e/euaOLEiX0gvQABxALzFygMQDEBsgmkGOgtsDjMAJDT\
QeKsrKwMQNfCwwMggMAu8Pf3jwb6dSkwXtlhgQXTAOODYkdQUJABGFZMQBd4AGPp+6VLl44CBBCz\
l5eXjZCQ0GoVFRU2kGKQRhiAhQfMJSB5UOyA8MePH12kpaWvAgQQs6qq6jR1dXUtkPORNcOcDooB\
ZDFQoIJiB+gixsePH0sDBBALOzu7KScnJ1bN9+7dA4X2Xy0tLWaYV0DioBQLshCoVwMggFiAAfIU\
mBrFgBywITDNd+/eZQDakA/0wovLly8vA+YBZpgFsFT7+fPntwABxAwMjG9ARYEgf4FsAfn54cOH\
DI8ePSrfuXNnH9AVV4F+vQvU4AnMcKwgw0EJDphXGJ48edINEECMIBPd3d0Tgc5KAHpFAhidd4EK\
5gA1r0POzs7Ozk5AZ2cBY0EX6Or3QK+tBqbOCQABBgCzBWGTrJ55PAAAAABJRU5ErkJggg=="

#define ICENA "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAAsTAAALEwEAmpwYAAAA\
BGdBTUEAALGOfPtRkwAAACBjSFJNAAB6JQAAgIMAAPn/AACA6QAAdTAAAOpgAAA6mAAAF2+SX8VG\
AAADKUlEQVR42mJgAAJpBgbNmQwMUy8yMOzoZ2CYKM7AoMOABtQYGMw2MjDMusTAsLOdgaGHh4FB\
HiQOEIBmObQBEIYCKPhSwwDNlyTdoB2DDoBgcRwKhy3BPjCcP+LLN5ympBGasw9cFZY/r7AJw9a0\
dy3FA/YJ5lcAhuTYBkAQAIDgD0HHChROQGVPIokjOIZzYOlIzEFha2Nerj1uuGZqjJqzlqIp+cGz\
wLrBPv+1Vu1dx9DWNAQPOH8BxGLCwKAKtuY/UNkXoFvY2IBu0mRgYmAQOH/lyiagDDuDszMTQ2oq\
A4OwMAODoCADg7Y2A4OQEIP6mzcKAAHEshXoFC0GBkeGjx8hmv/9Y2BgYgIbwvDjBycDBwcDg5cX\
A8Pv30CPPoZYdPUqA8OzZwzA8HgAEECMfEDzgIyDwBARZuDjA5sMtkVMjIGBhwdiq5wcA4OICNDH\
sgwMT54wMHR3M1y7c+epHgODA0AAMf9kYHgNdMUldwYGH+GfPzkY/gJ9z8gIsQnkIhYWiKtANMjm\
adMYLj98+NKBgSHiKwPDeYAAYgZ5/x0Dwx2gZ8+4MDAEiv/6xQ42BOQNkCEgzcxAZa9eMTCsWcNw\
8tWrN44MDAEfGBiOgvQCBBALLKqADhXiBtoJ5nz9CrEdpBHkGpDtXFwMDNzcDPzv3rEBPcb9CaoP\
IIDALgCGacRyBoaFwMTCAY+RX78gmmF8Tk5g0pFnEPn+nd3twwe/zQwMF4CG3AUIIGagaaaLGBjW\
mwGVoCQ9kKafPyFeABkEokGGAANU/OtXDu2PHz2WMjBsAgggZmBCaSkFJlMGbABkyI8fiHAAhQ0o\
WoFeUXn2jGvP378fAAKIBZgPFBlwgAnA1Ai0kz39wwcucKCCMMigP3/AbGCEywAEEIMzA0PfD4hd\
KHgaA8NLoFJrAQYGV6AX34PFBQT+/5eV/f9fTOw/SA8wqVUBBBDIIvk6YGr8BtUIkuhlYHgIjAN7\
mEuAyct9BgPD819QNcAE/7+AgeEsUEoKIICgwcwgDcw4iVLAIAKms0fAlAmMFIa76DkamG+igFld\
+j5Q7hoDwwKg2AuAAAMAa/8Fcw6Og8MAAAAASUVORK5CYII="

#define ICHID "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAAK/INwWK6QAAABl0RVh0\
U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAJdSURBVDjLpZP7S1NhGMf9W7YfogSJboSE\
UVCY8zJ31trcps6zTI9bLGJpjp1hmkGNxVz4Q6ildtXKXzJNbJRaRmrXoeWx8tJOTWptnrNryre5\
YCYuI3rh+8vL+/m8PA/PkwIg5X+y5mJWrxfOUBXm91QZM6UluUmthntHqplxUml2lciF6wrmdHri\
I0Wx3xw2hAediLwZRWRkCPzdDswaSvGqkGCfq8VEUsEyPF1O8Qu3O7A09RbRvjuIttsRbT6HHzeb\
sDjcB4/JgFFlNv9MnkmsEszodIIY7Oaut2OJcSF68Qx8dgv8tmqEL1gQaaARtp5A+N4NzB0lMXxo\
n/uxbI8gIYjB9HytGYuusfiPIQcN71kjgnW6VeFOkgh3XcHLvAwMSDPohOADdYQJdF1FtLMZPmsl\
vhZJk2ahkgRvq4HHUoWHRDqTEDDl2mDkfheiDgt8pw340/EocuClCuFvboQzb0cwIZgki4KhzlaE\
6w0InipbVzBfqoK/qRH94i0rgokSFeO11iBkp8EdV8cfJo0yD75aE2ZNRvSJ0lZKcBXLaUYmQrCz\
DT6tDN5SyRqYlWeDLZAg0H4JQ+Jt6M3atNLE10VSwQsN4Z6r0CBwqzXesHmV+BeoyAUri8EyMfi2\
FowXS5dhd7doo2DVII0V5BAjigP89GEVAtda8b2ehodU4rNaAW+dGfzlFkyo89GTlcrHYCLpKD+V\
7yeeHNzLjkp24Uu1Ed6G8/F8qjqGRzlbl2H2dzjpMg1KdwsHxOlmJ7GTeZC/nesXbeZ6c9OYnuxU\
c3fmBuFft/Ff8xMd0s65SXIb/gAAAABJRU5ErkJggg=="

#define ICRES "data:image/png;base64,\
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABmJLR0QA/wD/AP+gvaeTAAAACXBI\
WXMAAABIAAAASABGyWs+AAABVUlEQVQ4y6WSPUtCURjHf+d2vV5f0l5Mr0KQERbUYChJQ1D0FaKh\
phra/QBOQY3NYV+guZagMVxysVGIhhLELDQRzLidBlG8qSDcB85wznOe33nO//kLicROqKMSnrRm\
ITcv2mIsQLfQv6rj0jW8ut45R5PDIOr/YtWrEI77mXTqtKsmWstBeG6a1OHyUIja/6rucxBLGbiE\
RuHhle/WD0jJi/5OJDTDycHuAKTXQSxpEDGm8Oke7m6f+DxvDrRrZPzyaH/HAlG6AhXzZaIBg4VA\
kMRadEBEgPJpXVzf5NhMxHp5pf/CYjBEpfRFLl8cObb3s4Z4LDz39qLfB13qqJENC2HXSMKddgwY\
JosYm6oCZNJ7VBo1Lq/ue4njjQmEyw2zYcT8EmJlHeJbkNwG1QlAVogOoFSv8lb7sJDbJmgSkBJ+\
O0uYJpimxX62v2BbRMVWNfAHT997IDXV+VUAAAAASUVORK5CYII="

#define TPLHEADER "\
<HTML>\n\
<HEAD>\n\
	<TITLE>OSCAM ##CS_VERSION## build ###CS_SVN_VERSION##</TITLE>\n\
	<link rel=\"stylesheet\" type=\"text/css\" href=\"site.css\">\n\
	<link href=\"favicon.ico\" rel=\"icon\" type=\"image/x-icon\"/>\n\
##REFRESH##\
	<script type=\"text/javascript\" src=\"oscam.js\"></script>\n\
</HEAD>\n\
<BODY ##ONLOADSCRIPT##>\n\
	<DIV CLASS=\"header\"><H2 CLASS=\"headline1\">OSCAM ##CS_VERSION## build ###CS_SVN_VERSION##</H2></DIV>\n"

#define TPLAPIHEADER "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<oscam version=\"##CS_VERSION## build ###CS_SVN_VERSION##\" revision=\"##CS_SVN_VERSION##\" starttime=\"##APISTARTTIME##\" uptime=\"##APIUPTIME##\" readonly=\"##APIREADONLY##\">\n"

#define TPLAPIERROR "##TPLAPIHEADER##\n\
		<error>##APIERRORMESSAGE##</error>\n\
##TPLAPIFOOTER##"

#define TPLAPICONFIRMATION "##TPLAPIHEADER##\n\
		<confirm>##APICONFIRMMESSAGE##</confirm>\n\
##TPLAPIFOOTER##"

#define TPLFOOTER "\
	<BR><HR/><BR>\n\
	<DIV CLASS=\"footer\">\n\
		<H4 CLASS=\"footline1\">OSCAM Webinterface developed by Streamboard Team - ##CURDATE## ##CURTIME## | Access from ##CURIP##</H4>\n\
		<H4 CLASS=\"footline2\">Start: ##STARTDATE## - ##STARTTIME## | UpTime: ##UPTIME## | Process ID: ##PROCESSID##</H4>\n\
		<H4 CLASS=\"styleauthor\">WebIf Style by </H4>\n\
	</DIV>\n\
</BODY>\n\
</HTML>"

#define TPLAPIFOOTER "</oscam>"

#define TPLREFRESH "\
	<meta http-equiv=\"refresh\" content=\"##REFRESHTIME##; URL=##REFRESHURL##\" />\n"

#define TPLHELPPREFIX "<A HREF=\"http://streamboard.gmc.to/wiki/index.php/OSCam/##LANGUAGE##/Config/oscam."

#define TPLHELPSUFFIX "\" TARGET=\"_blank\">"

#define TPLMENU "\
	<TABLE border=0 class=\"menu\">\n\
		<TR>\n\
			<TD CLASS=\"menu\"><A HREF=\"status.html\">STATUS</TD>\n\
			<TD CLASS=\"menu\"><A HREF=\"config.html\">CONFIGURATION</TD>\n\
			<TD CLASS=\"menu\"><A HREF=\"readers.html\">READERS</TD>\n\
			<TD CLASS=\"menu\"><A HREF=\"userconfig.html\">USERS</TD>\n\
			<TD CLASS=\"menu\"><A HREF=\"services.html\">SERVICES</TD>\n\
			<TD CLASS=\"menu\"><A HREF=\"files.html\">FILES</TD>\n\
			<TD CLASS=\"menu\"><A HREF=\"failban.html\">FAILBAN</TD>\n\
			<TD CLASS=\"script\"><A HREF=\"script.html\">SCRIPT</TD>\n\
			<TD CLASS=\"shutdown\"><A HREF=\"shutdown.html\">SHUTDOWN</TD>\n\
		</TR>\n\
	</TABLE>\n"

#define TPLCONFIGMENU "\
	<BR><BR>\n\
	<TABLE border=0 class=\"configmenu\">\n\
		<TR>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=global\">Global</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=loadbalancer\">Loadbalancer</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=camd33\">Camd3.3</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=camd35\">Camd3.5</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=camd35tcp\">Camd3.5 TCP</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=newcamd\">Newcamd</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=radegast\">Radegast</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=cccam\">Cccam</TD>\n\
##TPLCONFIGMENUGBOX##\
##TPLCONFIGMENUANTICASC##\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=monitor\">Monitor</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=serial\">Serial</TD>\n\
##TPLCONFIGMENUDVBAPI##\
		</TR>\n\
	</TABLE>\n"

#define TPLFILEMENU "\
	<BR><BR>\n\
	<TABLE border=0 class=\"configmenu\">\n\
		<TR>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=version\">oscam.version</TD>\n\
##TPLFILEMENUDVBAPI##\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=conf\">oscam.conf</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=user\">oscam.user</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=server\">oscam.server</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=services\">oscam.services</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=srvid\">oscam.srvid</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=provid\">oscam.provid</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=tiers\">oscam.tiers</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=logfile\">logfile</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=userfile\">userfile</TD>\n\
##TPLFILEMENUANTICASC##\
		</TR>\n\
	</TABLE>"

#define TPLFILE "\
##TPLHEADER##\
##TPLMENU##\
##TPLFILEMENU##\n\
	<BR><BR>##SDEBUG####SLOG####SCLEAR##<BR>##FILTER##\n\
	<FORM ACTION=\"files.html\" method=\"post\">\n\
		<INPUT TYPE=\"hidden\" NAME=\"part\" VALUE=\"##PART##\">\n\
		<TEXTAREA NAME=\"filecontent\" CLASS=\"editor\">\n\
##FILECONTENT##\
		</TEXTAREA><BR>##WRITEPROTECTION##<BR>\n\
		<INPUT TYPE=\"submit\" NAME=\"action\" VALUE=\"Save\" TITLE=\"Save file\" ##BTNDISABLED##>\n\
	</FORM>\n\
##TPLFOOTER##"

#ifdef WITH_DEBUG
#define TPLDEBUGSELECT "\
	<SPAN CLASS=\"debugt\"> Switch Debug from&nbsp;##ACTDEBUG## to&nbsp;</SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"debugl\" HREF=\"##NEXTPAGE##?debug=0##CUSTOMPARAM##\" title=\"no debugging (default)\">&nbsp;0&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS1##\" HREF=\"##NEXTPAGE##?debug=##DEBUGVAL1####CUSTOMPARAM##\" title=\"detailed error messages\">&nbsp;1&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS2##\" HREF=\"##NEXTPAGE##?debug=##DEBUGVAL2####CUSTOMPARAM##\" title=\"ATR parsing info, ECM dumps, CW dumps\">&nbsp;2&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS4##\" HREF=\"##NEXTPAGE##?debug=##DEBUGVAL4####CUSTOMPARAM##\" title=\"traffic from/to the reader\">&nbsp;4&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS8##\" HREF=\"##NEXTPAGE##?debug=##DEBUGVAL8####CUSTOMPARAM##\" title=\"traffic from/to the clients\">&nbsp;8&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS16##\" HREF=\"##NEXTPAGE##?debug=##DEBUGVAL16####CUSTOMPARAM##\" title=\"traffic to the reader-device on IFD layer\">&nbsp;16&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS32##\" HREF=\"##NEXTPAGE##?debug=##DEBUGVAL32####CUSTOMPARAM##\" title=\"traffic to the reader-device on I/O layer\">&nbsp;32&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS64##\" HREF=\"##NEXTPAGE##?debug=##DEBUGVAL64####CUSTOMPARAM##\" title=\"EMM logging\">&nbsp;64&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS128##\" HREF=\"##NEXTPAGE##?debug=##DEBUGVAL128####CUSTOMPARAM##\" title=\"DVBAPI logging\">&nbsp;128&nbsp;</A></SPAN>\n\
	<SPAN CLASS=\"debugl\"><A CLASS=\"##DCLASS255##\" HREF=\"##NEXTPAGE##?debug=255##CUSTOMPARAM##\" title=\"debug all\">&nbsp;255&nbsp;</A></SPAN>\n"
#endif

#define TPLFAILBAN "\
##TPLHEADER##\
##TPLMENU##\
	<BR><BR>\n\
		<TABLE border=0 class=\"configmenu\">\n\
		<TR>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"failban.html?action=delete&intip=all\">Clear all</TD>\n\
		</TR>\n\
	</TABLE>\
	<BR><BR>\n\
	<TABLE CLASS=\"stats\">\n\
		<TR><TH colspan=\"5\">List of banned IP Addresses</TH></TR>\n\
		<TR><TH>IP Address</TH><TH>Violation date</TH><TH>Violation count</TH><TH>left ban time</TH><TH>Action</TH></TR>\n\
##FAILBANROW##\
	</TABLE><BR>\n\
##TPLFOOTER##"

#define TPLFAILBANBIT "\
		<TR>\n\
			<TD>##IPADDRESS##</TD>\
			<TD>##VIOLATIONDATE##</TD>\
			<TD>##VIOLATIONCOUNT##</TD>\
			<TD align=\"center\">##LEFTTIME##</TD>\
			<TD align=\"center\"><A HREF=\"failban.html?action=delete&intip=##INTIP##\" TITLE=\"Delete Entry\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICDEL\" BORDER=\"0\" ALT=\"Delete Entry\"/></A></TD>\n\
		</TR>\n"

#ifdef CS_ANTICASC
#define TPLCONFIGMENUANTICASC "			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=anticasc\">Anticascading</A></TD>\n"
#define TPLFILEMENUANTICASC "			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=anticasc\">AC Log</A></TD>\n"
#endif

#ifdef HAVE_DVBAPI
#define TPLCONFIGMENUDVBAPI "			<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=dvbapi\">DVB-Api</A></TD>\n"
#define TPLFILEMENUDVBAPI "			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=dvbapi\">oscam.dvbapi</A></TD>\n"
#endif

#define TPLSTATUS "\
##TPLHEADER##\
##TPLMENU##\
	<BR><BR>\n\
	<form action=\"status.html\" method=\"get\">\n\
		<select name=\"hideidle\">\n\
			<option value=\"0\" ##HIDEIDLECLIENTSSELECTED0##>Show idle clients</option>\n\
			<option value=\"1\" ##HIDEIDLECLIENTSSELECTED1##>Hide idle clients</option>\n\
			<option value=\"2\">Show hidden clients</option>\n\
		</select>\n\
		<input type=\"submit\" value=\"Update\">\n\
	</form>\n\
	<TABLE WIDTH=\"100%\" class=\"status\">\n\
		<TR>\n\
			<TH class=\"statuscol0\">hide</TH>\n\
			<TH class=\"statuscol1\">Thread ID</TH>\n\
			<TH class=\"statuscol2\">Type</TH>\n\
			<TH class=\"statuscol3\">ID</TH>\n\
			<TH class=\"statuscol4\">Label</TH>\n\
			<TH class=\"statuscol5\">AU</TH>\n\
			<TH class=\"statuscol6\">Crypted</TH>\n\
			<TH class=\"statuscol7\">Address</TH>\n\
			<TH class=\"statuscol8\">Port</TH>\n\
			<TH class=\"statuscol9\">Protocol</TH>\n\
			<TH class=\"statuscol10\">Login</TH>\n\
			<TH class=\"statuscol11\">Online</TH>\n\
			<TH class=\"statuscol12\">CAID:SRVID</TH>\n\
			<TH class=\"statuscol13\">Current Channel</TH>\n\
			<TH class=\"statuscol14\">LB Value/ Reader</TH>\n\
			<TH class=\"statuscol15\">Idle</TH>\n\
			<TH class=\"statuscol16\">Status</TH>\n\
		</TR>\n\
##SERVERSTATUS##\n\
##READERHEADLINE##\n\
##READERSTATUS##\n\
##PROXYHEADLINE##\n\
##PROXYSTATUS##\n\
##CLIENTHEADLINE##\n\
##CLIENTSTATUS##\n\
	</TABLE><BR>\n\
	<DIV class=\"log\">\n\
##LOGHISTORY##\
	</DIV><BR>\n\
##SDEBUG##\
##TPLFOOTER##"

#define TPLAPISTATUS "##TPLAPIHEADER##\n\
	<status>\n\
##APISTATUSBITS##\
	</status>\n\
	<log><![CDATA[ \n\
   ##LOGHISTORY##\
	]]></log>\
##TPLAPIFOOTER##"


#define TPLCLIENTSTATUSBIT "\
		<TR class=\"##CLIENTTYPE##\">\n\
			<TD class=\"statuscol0\"><A HREF =\"status.html?hide=##HIDEIDX##\" TITLE=\"Hide this client\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICHID\" ALT=\"Hide\"></A></TD>\n\
			<TD class=\"statuscol1\">##CSIDX##</TD>\n\
			<TD class=\"statuscol2\">##CLIENTTYPE##</TD>\n\
			<TD class=\"statuscol3\">##CLIENTCNR##</TD>\n\
			<TD class=\"statuscol4\"><SPAN TITLE=\"##CLIENTDESCRIPTION##\">##CLIENTUSER##</SPAN></TD>\n\
			<TD class=\"statuscol5\">##CLIENTCAUHTTP##</TD>\n\
			<TD class=\"statuscol6\">##CLIENTCRYPTED##</TD>\n\
			<TD class=\"statuscol7\">##CLIENTIP##</TD>\n\
			<TD class=\"statuscol8\">##CLIENTPORT##</TD>\n\
			<TD class=\"statuscol9\"><SPAN TITLE=\"##CLIENTPROTOTITLE##\">##CLIENTPROTO##</SPAN></TD>\n\
			<TD class=\"statuscol10\">##CLIENTLOGINDATE##</TD>\n\
			<TD class=\"statuscol11\">##CLIENTLOGINSECS##</TD>\n\
			<TD class=\"statuscol12\">##CLIENTCAID##:##CLIENTSRVID##</TD>\n\
			<TD class=\"statuscol13\">##CLIENTSRVPROVIDER####CLIENTSRVNAME##</TD>\n\
			<TD class=\"statuscol14\">##CLIENTLBVALUE##</TD>\n\
			<TD class=\"statuscol15\">##CLIENTIDLESECS##</TD>\n\
			<TD class=\"statuscol16\">##CLIENTCON##</TD>\n\
		</TR>\n"


#define TPLAPISTATUSBIT "      <client type=\"##CLIENTTYPE##\" name=\"##CLIENTUSER##\" protocol=\"##CLIENTPROTO##\" protocolext=\"##CLIENTPROTOTITLE##\" au=\"##CLIENTCAU##\">\n\
         <request caid=\"##CLIENTCAID##\" srvid=\"##CLIENTSRVID##\" ecmtime=\"##CLIENTLASTRESPONSETIME##\" ecmhistory=\"##CLIENTLASTRESPONSETIMEHIST##\" answered=\"##LASTREADER##\">##CLIENTSRVPROVIDER####CLIENTSRVNAME##</request>\n\
         <times login=\"##CLIENTLOGINDATE##\" online=\"##CLIENTLOGINSECS##\" idle=\"##CLIENTIDLESECS##\"></times>\n\
         <connection ip=\"##CLIENTIP##\" port=\"##CLIENTPORT##\">##CLIENTCON##</connection>\n\
      </client>\n"


#define TPLAPIUSERCONFIGLIST "##TPLAPIHEADER##\n\
    <users>\n\
##APIUSERCONFIGS##\
    </users>\n\
    <totals>\n\
        <cwok>##TOTAL_CWOK##</cwok>\n\
        <cwnok>##TOTAL_CWNOK##</cwnok>\n\
        <cwignore>##TOTAL_CWIGN##</cwignore>\n\
        <cwtimeout>##TOTAL_CWTOUT##</cwtimeout>\n\
        <cwcache>##TOTAL_CWCACHE##</cwcache>\n\
        <cwtun>##TOTAL_CWTUN##</cwtun>\n\
    </totals>\n\
##TPLAPIFOOTER##"

#define TPLAPIUSERCONFIGLISTBIT "        <user name=\"##USER##\">\n\
            <stats>\n\
                <cwok>##CWOK##</cwok>\n\
                <cwnok>##CWNOK##</cwnok>\n\
                <cwignore>##CWIGN##</cwignore>\n\
                <cwtimeout>##CWTOUT##</cwtimeout>\n\
                <cwcache>##CWCACHE##</cwcache>\n\
                <cwtun>##CWTUN##</cwtun>\n\
                <cwlastresptime>##CWLASTRESPONSET##</cwlastresptime>\n\
                <emmok>##EMMOK##</emmok>\n\
                <emmnok>##EMMNOK##</emmnok>\n\
                <cwrate>##CWRATE##</cwrate>\n\
            </stats>\n\
        </user>\n"


#define TPLUSERCONFIGLIST "\
##TPLHEADER##\
##TPLMENU##\
##MESSAGE##\
	<BR>\n\
	<TABLE CLASS=\"configmenu\">\n\
		<TR>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"userconfig.html?part=adduser\">Add User</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"userconfig.html?action=reinit\">Reinit User DB</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"userconfig.html?action=resetalluserstats\">Reset Userstats</TD>\n\
		</TR>\n\
	</TABLE><BR>\n\
	<TABLE CLASS=\"users\">\n\
		<TR>\n\
			<TH>Lock</TH>\n\
			<TH>Label</TH>\n\
			<TH>Status</TH>\n\
			<TH>Protocol</TH>\n\
			<TH>Last Channel</TH>\n\
			<TH>Idle</TH>\n\
			<TH>OK</TH>\n\
			<TH>NOK</TH>\n\
			<TH>IGN</TH>\n\
			<TH>TOUT</TH>\n\
			<TH>CACHE</TH>\n\
			<TH>TUN</TH>\n\
			<TH>LTIME</TH>\n\
			<TH>EOK</TH>\n\
			<TH>ENOK</TH>\n\
			<TH>CW Rate</TH>\n\
			<TH colspan=\"3\" align=\"center\">Action</TH>\n\
		</TR>\n\
##USERCONFIGS##\
##NEWUSERFORM##\
	</TABLE><BR>\n\
	<TH>Totals for the server: </TH>\n\
	<TABLE cellpadding=\"10\">\n\
		<TR>\n\
			<TH>OK</TH>\n\
			<TH>NOK</TH>\n\
			<TH>IGN</TH>\n\
			<TH>TOUT</TH>\n\
			<TH>CACHE</TH>\n\
			<TH>TUN</TH>\n\
			<TH>Action</TH>\n\
		</TR>\n\
		<TR>\n\
			<TD align=\"center\">##TOTAL_CWOK##</TD>\n\
			<TD align=\"center\">##TOTAL_CWNOK##</TD>\n\
			<TD align=\"center\">##TOTAL_CWIGN##</TD>\n\
			<TD align=\"center\">##TOTAL_CWTOUT##</TD>\n\
			<TD align=\"center\">##TOTAL_CWCACHE##</TD>\n\
			<TD align=\"center\">##TOTAL_CWTUN##</TD>\n\
			<TD align=\"center\"><A HREF=\"userconfig.html?action=resetserverstats\" TITLE=\"reset statistics for server\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICRES\"BORDER=\"0\" ALT=\"Reset Server Stats\"/></A></TD>\n\
		</TR>\n\
	</TABLE><BR>\n\
##TPLFOOTER##"

#define TPLADDNEWUSER "\
		<TR>\n\
		<FORM action=\"user_edit.html\" method=\"get\">\n\
		<TD>&nbsp;</TD>\n\
		<TD colspan=\"6\">New User:&nbsp;&nbsp;<input name=\"user\" type=\"text\">&nbsp;&nbsp;&nbsp;<input type=\"submit\" value=\"Add User\" ##BTNDISABLED##></TD>\n\
		<TD colspan=\"10\" align=\"center\"></TD>\n\
		</FORM>\n\
		<TR>\n"

#define TPLUSERCONFIGLISTBIT "\
		<TR class=\"##CLASSNAME##\">\n\
			<TD align=\"center\"><A HREF=\"userconfig.html?user=##USERENC##&action=##SWITCH##\" TITLE=\"##SWITCHTITLE##\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"##SWITCHICO##\"BORDER=\"0\" ALT=\"##SWITCHTITLE##\"/></A></TD>\n\
			<TD><SPAN TITLE=\"##DESCRIPTION##\">##USER##</SPAN></TD>\n\
			<TD>##STATUS##</TD>\n\
			<TD align=\"center\"><SPAN TITLE=\"##CLIENTPROTOTITLE##\">##CLIENTPROTO##</SPAN></TD>\n\
			<TD>##LASTCHANNEL##</TD>\n\
			<TD align=\"center\">##IDLESECS##</TD>\n\
			<TD align=\"center\">##CWOK##</TD>\n\
			<TD align=\"center\">##CWNOK##</TD>\n\
			<TD align=\"center\">##CWIGN##</TD>\n\
			<TD align=\"center\">##CWTOUT##</TD>\n\
			<TD align=\"center\">##CWCACHE##</TD>\n\
			<TD align=\"center\">##CWTUN##</TD>\n\
			<TD align=\"center\">##CWLASTRESPONSET##</TD>\n\
			<TD align=\"center\">##EMMOK##</TD>\n\
			<TD align=\"center\">##EMMNOK##</TD>\n\
			<TD align=\"center\">##CWRATE####CWRATE2##</TD>\n\
			<TD align=\"center\"><A HREF=\"user_edit.html?user=##USERENC##\" TITLE=\"edit this user\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICEDI\" BORDER=\"0\" ALT=\"Edit User\"/></A></TD>\n\
			<TD align=\"center\"><A HREF=\"userconfig.html?user=##USERENC##&action=resetstats\" TITLE=\"reset statistics for this user\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICRES\"BORDER=\"0\" ALT=\"Reset Stats\"/></A></TD>\n\
			<TD align=\"center\"><A HREF=\"userconfig.html?user=##USERENC##&action=delete\" TITLE=\"delete this user\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICDEL\"BORDER=\"0\" ALT=\"Delete User\"/></A></TD>\n\
		</TR>\n"

#define TPLUSEREDIT "\
##TPLHEADER##\
##TPLMENU##\
	<DIV CLASS=\"message\">##MESSAGE##</DIV>\
	<BR><BR>\n\
	<form action=\"user_edit.html\" method=\"get\">\n\
		<input name=\"user\" type=\"hidden\" value=\"##USERNAME##\">\n\
		<TABLE CLASS=\"config\">\n\
			<TR><TH>&nbsp;</TH> <TH>Edit User ##USERNAME##</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#pwd##TPLHELPSUFFIX##Password:</A></TD><TD><input name=\"pwd\" type=\"text\" size=\"63\" maxlength=\"63\" value=\"##PASSWORD##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#description##TPLHELPSUFFIX##Description:</A></TD><TD><input name=\"description\" type=\"text\" size=\"63\" maxlength=\"63\" value=\"##DESCRIPTION##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#disabled##TPLHELPSUFFIX##Disabled:</A></TD><TD><SELECT NAME=\"disabled\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##DISABLEDCHECKED##>YES</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#expdate##TPLHELPSUFFIX##Exp. Date:</A></TD><TD><input name=\"expdate\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##EXPDATE##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#failban##TPLHELPSUFFIX##Failban:</A></TD><TD><input name=\"failban\" type=\"text\" size=\"2\" maxlength=\"1\" value=\"##FAILBAN##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#allowedtimeframe##TPLHELPSUFFIX##Allowed Timeframe:</A></TD><TD><input name=\"allowedtimeframe\" type=\"text\" size=\"15\" maxlength=\"11\" value=\"##ALLOWEDTIMEFRAME##\">&nbsp;(hh:mm-hh:mm)</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#group##TPLHELPSUFFIX##Group:</A></TD><TD><input name=\"group\" type=\"text\" size=\"20\" maxlength=\"100\" value=\"##GROUPS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#hostname##TPLHELPSUFFIX##Hostname:</A></TD><TD><input name=\"hostname\" type=\"text\" size=\"60\" maxlength=\"50\" value=\"##DYNDNS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#uniq##TPLHELPSUFFIX##Uniq:</A></TD>\n\
				<TD>\n\
					<select name=\"uniq\">\n\
						<option value=\"0\" ##UNIQSELECTED0##>0 - none</option>\n\
						<option value=\"1\" ##UNIQSELECTED1##>1 - strict first</option>\n\
						<option value=\"2\" ##UNIQSELECTED2##>2 - per IP</option>\n\
						<option value=\"3\" ##UNIQSELECTED3##>3 - strict last</option>\n\
						<option value=\"4\" ##UNIQSELECTED4##>4 - per IP last</option>\n\
					</select>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#sleep##TPLHELPSUFFIX##Sleep:</A></TD><TD><input name=\"sleep\" type=\"text\" size=\"4\" maxlength=\"4\" value=\"##SLEEP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#monlevel##TPLHELPSUFFIX##Monlevel:</A></TD>\n\
				<TD>\n\
					<select name=\"monlevel\">\n\
						<option value=\"0\" ##MONSELECTED0##>0 - no access to monitor</option>\n\
						<option value=\"1\" ##MONSELECTED1##>1 - only server and own procs</option>\n\
						<option value=\"2\" ##MONSELECTED2##>2 - all procs, but viewing only, default</option>\n\
						<option value=\"3\" ##MONSELECTED3##>3 - all procs, reload of oscam.user possible</option>\n\
						<option value=\"4\" ##MONSELECTED4##>4 - complete access</option>\n\
					</select>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#au##TPLHELPSUFFIX##AU:</A></TD><TD><input name=\"au\" type=\"text\" size=\"60\" maxlength=\"50\" value=\"##AUREADER##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#services##TPLHELPSUFFIX##Services:</A></TD>\n\
				<TD>\n\
					<TABLE class=\"invisible\">\n\
##SIDS##\
					</TABLE>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#caid##TPLHELPSUFFIX##CAID:</A></TD><TD><input name=\"caid\" type=\"text\" size=\"60\" maxlength=\"50\" value=\"##CAIDS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#ident##TPLHELPSUFFIX##Ident:</A></TD><TD><textarea name=\"ident\" cols=\"58\" rows=\"3\" class=\"bt\">##IDENTS##</textarea></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#chid##TPLHELPSUFFIX##CHID:</A></TD><TD><textarea name=\"chid\" cols=\"58\" rows=\"3\" class=\"bt\">##CHIDS##</textarea></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#betatunnel##TPLHELPSUFFIX##Betatunnel:</A></TD><TD><textarea name=\"betatunnel\" cols=\"58\" rows=\"3\" class=\"bt\">##BETATUNNELS##</textarea></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#suppresscmd08##TPLHELPSUFFIX##Suppresscmd08:</A></TD><TD><SELECT NAME=\"suppresscmd08\"><OPTION VALUE=\"0\">CMD08 active</OPTION><OPTION VALUE=\"1\" ##SUPPRESSCMD08##>CMD08 suppressed</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#sleepsend##TPLHELPSUFFIX##Sleepsend:</A></TD><TD><input name=\"sleepsend\" type=\"text\" size=\"3\" maxlength=\"3\" value=\"##SLEEPSEND##\"> 0 or 255</TD></TR>\n\
##TPLUSEREDITANTICASC##\
			<TR class=\"usrcfg_cccam\"><TD>##TPLHELPPREFIX##user#cccmaxhops##TPLHELPSUFFIX##CCC Maxhops:</A></TD><TD><input name=\"cccmaxhops\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##CCCMAXHOPS##\"></TD></TR>\n\
			<TR class=\"usrcfg_cccam\"><TD>##TPLHELPPREFIX##user#cccreshare##TPLHELPSUFFIX##CCC Reshare:</A></TD><TD><input name=\"cccreshare\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##CCCRESHARE##\"></TD></TR>\n\
			<TR class=\"usrcfg_cccam\"><TD>##TPLHELPPREFIX##user#cccignorereshare##TPLHELPSUFFIX##CCC Ignore reshare:</A></TD><TD><SELECT NAME=\"cccignorereshare\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##CCCIGNORERESHARE##>ON</OPTION></SELECT></TD></TR>\n\
			<TR class=\"usrcfg_cccam\"><TD>##TPLHELPPREFIX##user#cccstealth##TPLHELPSUFFIX##CCC stealth:</A></TD><TD><SELECT NAME=\"cccstealth\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##CCCSTEALTH##>ON</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##user#keepalive##TPLHELPSUFFIX##Keepalive:</A></TD><TD><SELECT NAME=\"keepalive\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##KEEPALIVE##>ON</OPTION></SELECT></TD></TR>\n\
			<TR>\n\
				<TD align=\"center\"><input type=\"submit\" name=\"action\" value=\"Save\" title=\"Save settings and reload users\" ##BTNDISABLED##></TD>\n\
				<TD align=\"center\"><input name=\"newuser\" type=\"text\" size=\"20\" maxlength=\"20\" title=\"Enter new username if you want to clone this user\">&nbsp;&nbsp;&nbsp;<input type=\"submit\" name=\"action\" value=\"Save As\" title=\"Save as new user and reload users\" ##BTNDISABLED##></TD>\n\
			</TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLUSEREDITRDRSELECTED "						<option value=\"##READERNAME##\" ##SELECTED##>##READERNAME##</option>"

#define TPLUSEREDITSIDOKBIT "\
						<TR>\n\
							<TD><INPUT NAME=\"services\" TYPE=\"CHECKBOX\" VALUE=\"##SIDLABEL##\" ##CHECKED##> ##SIDLABEL##</TD>\n"

#define TPLUSEREDITSIDNOBIT "\
							<TD><INPUT NAME=\"services\" TYPE=\"CHECKBOX\" VALUE=\"!##SIDLABEL##\" ##CHECKED##> !##SIDLABEL##</TD>\n\
						</TR>\n"

#ifdef CS_ANTICASC
# define TPLUSEREDITANTICASC "\
			<TR class=\"usrcfg_anticasc\"><TD>##TPLHELPPREFIX##user#numusers##TPLHELPSUFFIX##Anticascading numusers:</A></TD><TD><input name=\"numusers\" type=\"text\" size=\"3\" maxlength=\"3\" value=\"##AC_USERS##\"></TD></TR>\n\
			<TR class=\"usrcfg_anticasc\"><TD>##TPLHELPPREFIX##user#penalty##TPLHELPSUFFIX##Anticascading penalty:</A></TD>\
			<TD>\
			<select name=\"penalty\">\n\
					<option value=\"0\" ##PENALTY0##>0 - Only write to log</option>\n\
					<option value=\"1\" ##PENALTY1##>1 - Fake DW</option>\n\
					<option value=\"2\" ##PENALTY2##>2 - Ban</option>\n\
					<option value=\"3\" ##PENALTY3##>3 - Fake DW delayed</option>\n\
				</select>\n\
			</TD></TR>\n"
#endif

#define TPLSIDTAB "\
##TPLHEADER##\
##TPLMENU##\
	<BR><BR><DIV class=\"log\">\n\
##SIDTABS##\
	</DIV>\n\
##TPLFOOTER##"

#define TPLSIDTABBIT "\
	label=##LABEL##<BR>\n\
	caid(##CAIDNUM##)=##CAIDS##<BR>\n\
	provider(##PROVIDNUM##)=##PROVIDS##<BR>\n\
	services(##SRVIDNUM##)=##SRVIDS##<BR><BR>\n"

#define TPLREADERS "\
##TPLHEADER##\
##TPLMENU##\
	<BR><BR>\n\
	<TABLE CLASS=\"configmenu\"><TR><TD CLASS=\"configmenu\"><A HREF=\"scanusb.html\">Scan USB</A></TD></TR></TABLE><BR>\
	<form action=\"readerconfig.html\" method=\"get\">\n\
		<TABLE CLASS=\"readers\">\n\
			<TR>\n\
				<TH>Lock</TH>\n\
				<TH>Reader</TH>\n\
				<TH>Protocol</TH>\n\
				<TH>EMM error<br><span title=\"unknown EMM\"> UK </span>/<span title=\"global EMM\"> G </span>/<span title=\"shared EMM\"> S </span>/<span title=\"unique EMM\"> UQ </span></TH>\n\
				<TH>EMM written<br><span title=\"unknown EMM\"> UK </span>/<span title=\"global EMM\"> G </span>/<span title=\"shared EMM\"> S </span>/<span title=\"unique EMM\"> UQ </span></TH>\n\
				<TH>EMM skipped<br><span title=\"unknown EMM\"> UK </span>/<span title=\"global EMM\"> G </span>/<span title=\"shared EMM\"> S </span>/<span title=\"unique EMM\"> UQ </span></TH>\n\
				<TH>EMM blocked<br><span title=\"unknown EMM\"> UK </span>/<span title=\"global EMM\"> G </span>/<span title=\"shared EMM\"> S </span>/<span title=\"unique EMM\"> UQ </span></TH>\n\
				<TH COLSPAN=\"5\">Action</TH>\n\
			</TR>\n\
##READERLIST##\n\
			<TR>\n\
				<TD>&nbsp;</TD>\
				<TD COLSPAN=\"2\" align=\"center\">New Reader</TD>\n\
				<TD COLSPAN=\"2\" align=\"center\">Label:&nbsp;&nbsp;<input type=\"text\" name=\"label\" value=\"##NEXTREADER##\"></TD>\n\
				<TD COLSPAN=\"2\" align=\"center\">Protocol:&nbsp;&nbsp;\n\
					<select name=\"protocol\">\n\
						<option>mouse</option>\n\
						<option>mp35</option>\n\
						<option>smartreader</option>\n\
						<option>internal</option>\n\
						<option>sc8in1</option>\n\
						<option>serial</option>\n\
						<option>camd35</option>\n\
						<option>cs378x</option>\n\
						<option>radegast</option>\n\
						<option>newcamd</option>\n\
						<option>newcamd524</option>\n\
						<option>cccam</option>\n\
						<option>constcw</option>\n\
##ADDPROTOCOL##\n\
					</select>\n\
				</TD>\n\
				<TD COLSPAN=\"5\" align=\"center\"><input type=\"submit\" name=\"action\" value=\"Add\" ##BTNDISABLED##></TD>\n\
			</TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLREADERSBIT "\
			<TR CLASS =\"##READERCLASS##\">\n\
				<TD align=\"center\"><A HREF=\"readers.html?label=##READERNAMEENC##&action=##SWITCH##\" TITLE=\"##SWITCHTITLE##\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"##SWITCHICO##\"BORDER=\"0\" ALT=\"##SWITCHTITLE##\"/></A></TD>\n\
				<TD>##READERNAME##</TD>\n\
				<TD>##CTYP##</TD>\n\
				<TD align=\"center\">##EMMERRORUK## / ##EMMERRORG## / ##EMMERRORS## / ##EMMERRORUQ##</TD>\n\
				<TD align=\"center\">##EMMWRITTENUK## / ##EMMWRITTENG## / ##EMMWRITTENS## / ##EMMWRITTENUQ##</TD>\n\
				<TD align=\"center\">##EMMSKIPPEDUK## / ##EMMSKIPPEDG## / ##EMMSKIPPEDS## / ##EMMSKIPPEDUQ##</TD>\n\
				<TD align=\"center\">##EMMBLOCKEDUK## / ##EMMBLOCKEDG## / ##EMMBLOCKEDS## / ##EMMBLOCKEDUQ##</TD>\n\
				<TD align=\"center\"><A HREF=\"readerconfig.html?label=##READERNAMEENC##\" TITLE=\"Edit this Reader\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICEDI\" BORDER=\"0\" ALT=\"Edit Reader\"/></A></TD>\n\
				<TD align=\"center\">##ENTITLEMENT##</TD>\n\
				<TD align=\"center\">##READERREFRESH##</TD>\n\
				<TD align=\"center\"><A HREF=\"readerstats.html?label=##READERNAMEENC##&hide=4\" TITLE=\"Show loadbalancer statistics\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICSTA\" BORDER=\"0\" ALT=\"Loadbalancer statistics\"/></A></TD>\n\
				<TD align=\"center\"><A HREF=\"readers.html?label=##READERNAMEENC##&action=delete\" TITLE=\"Delete this Reader\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICDEL\" BORDER=\"0\" ALT=\"Delete Reader\"/></A></TD>\n\
			</TR>\n"

#define TPLREADERENTITLEBIT "<A HREF=\"entitlements.html?label=##READERNAMEENC##\" TITLE=\"Show Entitlement\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"##ENTICO##\" BORDER=\"0\" ALT=\"Show Entitlement\"/></A>"

#define TPLREADERREFRESHBIT "<A HREF=\"readers.html?action=reread&label=##READERNAMEENC##\" TITLE=\"Refresh Entitlement\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"##REFRICO##\" BORDER=\"0\" ALT=\"Reset and reload Entitlement\"/></A>"

#define TPLREADERSTATS "\
##TPLHEADER##\
##TPLMENU##\
	<DIV CLASS=\"message\">##MESSAGE##</DIV>\
	<BR><BR>\n\
	<TABLE border=0 class=\"configmenu\">\n\
		<TR>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"readerstats.html?label=##ENCODEDLABEL##&hide=-1\">show all</A></TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"readerstats.html?label=##ENCODEDLABEL##&hide=4\">hide 'not found'</A></TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"readerstats.html?label=##ENCODEDLABEL##&action=resetstat\">reset statistics</A>\
		</TR>\n\
	</TABLE>\n\
	<BR><BR>\n\
	<TABLE CLASS=\"stats\">\n\
	<TR><TH colspan=\"8\"> Loadbalance statistics for reader ##LABEL##</TH></TR>\n\
	<TR><TH>Channel</TH><TH>Channelname</TH><TH>ECM Length</TH><TH>Result</TH><TH>Avg-Time</TH><TH>Last-Time</TH><TH>Count</TH><TH>Last checked/ found</TH></TR>\n\
##READERSTATSROWFOUND##\
##READERSTATSNFHEADLINE##\
##READERSTATSROWNOTFOUND##\
	</TABLE>\n\
	<br>Total ECM count: ##TOTALECM##<br>\n\
##TPLFOOTER##"

#define TPLREADERSTATSBIT "\
		<TR><TD>##CHANNEL##</TD>\
		<TD>##CHANNELNAME##</TD>\
		<TD align=\"center\">##ECMLEN##</TD>\
		<TD align=\"center\">##RC##</TD>\
		<TD align=\"center\">##TIME##</TD>\
		<TD align=\"center\">##TIMELAST##</TD>\
		<TD align=\"center\">##COUNT##</TD>\
		<TD align=\"center\">##LAST##</TD></TR>\n"

#define TPLSCANUSB "\
##TPLHEADER##\
##TPLMENU##\
	<DIV CLASS=\"message\">##MESSAGE##</DIV>\
	<BR><BR>\n\
	<TABLE cellpadding=\"10\">\n\
		<TR><TH>USB Devices</TH></TR>\n\
##USBBIT##\n\
	</TABLE>\n\
##TPLFOOTER##"

#define TPLSCANUSBBIT "		<TR ##USBENTRYCLASS##><TD>##USBENTRY##</TD></TR>\n"

#define TPLENTITLEMENTS "\
##TPLHEADER##\
##TPLMENU##\
	<DIV CLASS=\"message\">##MESSAGE##</DIV>\
	<BR><BR>Entitlements for ##READERNAME##<BR><BR>\n\
##ENTITLEMENTCONTENT##\
##TPLFOOTER##"

#define TPLENTITLEMENTGENERICBIT "\
	<DIV class=\"log\">\n\
##LOGSUMMARY##\n\
##LOGHISTORY##\n\
	</DIV>\n"

#define TPLENTITLEMENTCCCAMBIT "\
	<TABLE CLASS=\"stats\">\
		<TR><TH>Host</TH><TH>Caid</TH><TH>System</TH><TH>share id</TH><TH>remote id</TH><TH>Uphops</TH><TH>Reshare</TH><TH>Providers</TH><TH>Nodes</TH><TH>Good sids</TH><TH>Bad sids</TH></TR>\
##CCCAMSTATSENTRY##\
	</TABLE>\n\
	<BR><DIV CLASS=\"cccamentitlementtotals\">##TOTALS##</DIV>\
	<BR><DIV CLASS=\"cccamentitlementcontrols\">##CONTROLS##</DIV>"

#define TPLENTITLEMENTCCCAMENTRYBIT "\
		<TR><TD>##HOST##</TD><TD>##CAID##</TD><TD>##SYSTEM##</TD><TD>##SHAREID##</TD><TD>##REMOTEID##</TD><TD>##UPHOPS##</TD><TD>##MAXDOWN##</TD><TD>##PROVIDERS##</TD><TD>##NODES##</TD><TD>##SERVICESGOOD##</TD><TD>##SERVICESBAD##</TD></TR>"

#define TPLAPICCCAMCARDLIST "##TPLAPIHEADER##\
	<reader label=\"##READERNAME##\" hostaddress=\"##APIHOST##\" hostport=\"##APIHOSTPORT##\">\n\
		<cardlist totalcards=\"##APITOTALCARDS##\">\n\
##CARDLIST##\n\
		</cardlist>\n\
	</reader>\n\
##TPLAPIFOOTER##"

#define TPLAPICCCAMCARDBIT "		<card number=\"##APICARDNUMBER##\" caid=\"##APICAID##\" system=\"##SYSTEM##\" \
reshare=\"##MAXDOWN##\" hop=\"##UPHOPS##\">\n\
			<shareid>##SHAREID##</shareid>\n\
			<remoteid>##REMOTEID##</remoteid>\n\
			<providers totalproviders=\"##APITOTALPROVIDERS##\">\n\
##PROVIDERLIST##\n\
			</providers>\n\
			<nodes totalnodes=\"##APITOTALNODES##\">\n\
##NODELIST##\n\
			</nodes>\n\
		</card>\n"

#define TPLAPICCCAMCARDPROVIDERBIT "				<provider number=\"##APIPROVIDERNUMBER##\" sa=\"##APIPROVIDERSA##\" \
caid=\"##APIPROVIDERCAID##\" \
provid=\"##APIPROVIDERPROVID##\">##APIPROVIDERNAME##</provider>\n"

#define TPLAPICCCAMCARDNODEBIT "				<node number=\"##APINODENUMBER##\">##APINODE##</node>\n"

#define TPLAPIREADERSTATS "##TPLAPIHEADER##\
	<reader label=\"##READERNAME##\">\n\
		<emmstats totalwritten=\"##TOTALWRITTEN##\" totalskipped=\"##TOTALSKIPPED##\" totalblocked=\"##TOTALBLOCKED##\" totalerror=\"##TOTALERROR##\">\n\
##EMMSTATS##\n\
		</emmstats>\n\
		<ecmstats count=\"##ROWCOUNT##\" totalecm=\"##TOTALECM##\" lastaccess=\"##LASTACCESS##\">\n\
##ECMSTATS##\n\
		</ecmstats>\n\
	</reader>\n\
##TPLAPIFOOTER##"

#define TPLAPIREADERSTATSEMMBIT "			<emm type=\"##EMMTYPE##\" result=\"##EMMRESULT##\">##EMMCOUNT##</emm>\n"

#define TPLAPIREADERSTATSECMBIT "			<ecm caid=\"##ECMCAID##\" provid=\"##ECMPROVID##\" srvid=\"##ECMSRVID##\"\
 channelname=\"##ECMCHANNELNAME##\" avgtime=\"##ECMTIME##\" lasttime=\"##ECMTIMELAST##\" rc=\"##ECMRC##\" rcs=\"##ECMRCS##\" lastrequest=\"##ECMLAST##\">##ECMCOUNT##</ecm>\n"

#define TPLREADERCONFIG "\
##TPLHEADER##\
##TPLMENU##\
	<BR><BR>\n\
##MESSAGE##\n\
	<form action=\"readerconfig.html?action=execute\" method=\"get\">\n\
		<input name=\"label\" type=\"hidden\" value=\"##READERNAME##\">\n\
		<input name=\"protocol\" type=\"hidden\" value=\"##PROTOCOL##\">\n\
		<TABLE CLASS=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Reader ##READERNAME##</TH></TR>\n\
			<TR><TH>&nbsp;</TH><TH>Reader general settings</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#enable##TPLHELPSUFFIX##Enable:</A></TD><TD><input name=\"enable\" type=\"hidden\" value=\"0\"><input name=\"enable\" type=\"checkbox\" value=\"1\" ##ENABLED##></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#device##TPLHELPSUFFIX##Device:</A></TD><TD><input name=\"device\" type=\"text\" size=\"60\" maxlength=\"150\" value=\"##DEVICE##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#group##TPLHELPSUFFIX##Group:</A></TD><TD><input name=\"group\" type=\"text\" size=\"20\" maxlength=\"100\" value=\"##GRP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#fallback##TPLHELPSUFFIX##Fallback:</A></TD><TD><input name=\"fallback\" type=\"hidden\" value=\"0\"><input name=\"fallback\" type=\"checkbox\" value=\"1\" ##FALLBACKCHECKED##></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#lb_weight##TPLHELPSUFFIX##Loadbalance weight:</A></TD><TD><input name=\"lb_weight\" type=\"text\" size=\"5\" maxlength=\"4\" value=\"##LBWEIGHT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#caid##TPLHELPSUFFIX##Caid:</A></TD><TD><input name=\"caid\" type=\"text\" size=\"60\" maxlength=\"100\" value=\"##CAIDS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#ident##TPLHELPSUFFIX##Ident:</A></TD><TD><textarea name=\"ident\" cols=\"58\" rows=\"3\" class=\"bt\">##IDENTS##</textarea></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#chid##TPLHELPSUFFIX##CHID:</A></TD><TD><textarea name=\"chid\" cols=\"58\" rows=\"3\" class=\"bt\">##CHIDS##</textarea></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#services##TPLHELPSUFFIX##Services:</A></TD>\n\
				<TD>\n\
					<TABLE class=\"invisible\">\n\
##SIDS##\
					</TABLE>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#audisabled##TPLHELPSUFFIX##AU disabled:</A></TD><TD><input name=\"audisabled\" type=\"hidden\" value=\"0\"><input name=\"audisabled\" type=\"checkbox\" value=\"1\" ##AUDISABLED##></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#auprovid##TPLHELPSUFFIX##AU Provid:</A></TD><TD><input name=\"auprovid\" type=\"text\" size=\"10\" maxlength=\"6\" value=\"##AUPROVID##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#emmcache##TPLHELPSUFFIX##Emmcache:</A></TD><TD><input name=\"emmcache\" type=\"text\" size=\"10\" maxlength=\"10\" value=\"##EMMCACHE##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#blockemm-u##TPLHELPSUFFIX##Blockemm:</A></TD>\n\
			<TD>\n\
				<TABLE class=\"invisible\">\n\
					<TR><TD align=\"center\">unknown</TD><TD align=\"center\">unique</TD><TD align=\"center\">shared</TD><TD align=\"center\">global</TD></TR>\n\
					<TR>\n\
						<TD align=\"center\"><input name=\"blockemm-unknown\" type=\"hidden\" value=\"0\"><input name=\"blockemm-unknown\" type=\"checkbox\" value=\"1\" ##BLOCKEMMUNKNOWNCHK##></TD>\n\
						<TD align=\"center\"><input name=\"blockemm-u\" type=\"hidden\" value=\"0\"><input name=\"blockemm-u\" type=\"checkbox\" value=\"1\" ##BLOCKEMMUNIQCHK##></TD>\n\
						<TD align=\"center\"><input name=\"blockemm-s\" type=\"hidden\" value=\"0\"><input name=\"blockemm-s\" type=\"checkbox\" value=\"1\" ##BLOCKEMMSHAREDCHK##></TD>\n\
						<TD align=\"center\"><input name=\"blockemm-g\" type=\"hidden\" value=\"0\"><input name=\"blockemm-g\" type=\"checkbox\" value=\"1\" ##BLOCKEMMGLOBALCHK##></TD>\n\
					</TR>\n\
				</TABLE>\n\
			</TD>\n\
			<TR><TH>&nbsp;</TH><TH>Reader specific settings for protocol ##PROTOCOL##</TH></TR>\n\
##READERDEPENDINGCONFIG##\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" name=\"action\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
	<BR><BR>\n\
##TPLFOOTER##"
#define TPLSAVETEMPLATES "##TPLHEADER##\
##TPLMENU##\
	<br><b>Saved ##CNT## templates to ##PATH##</b><br>\n\
##TPLFOOTER##"

#define TPLREADERCONFIGSIDOKBIT "\
						<TR>\n\
							<TD><INPUT NAME=\"services\" TYPE=\"CHECKBOX\" VALUE=\"##SIDLABEL##\" ##CHECKED##> ##SIDLABEL##</TD>\n"

#define TPLREADERCONFIGSIDNOBIT "\
							<TD><INPUT NAME=\"services\" TYPE=\"CHECKBOX\" VALUE=\"!##SIDLABEL##\" ##CHECKED##> !##SIDLABEL##</TD>\n\
						</TR>\n"

#define TPLREADERCONFIGSTDHWREADERBIT "\
				<TR><TD>##TPLHELPPREFIX##server#mhz##TPLHELPSUFFIX##Mhz:</A></TD><TD><input name=\"mhz\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##MHZ##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#cardmzh##TPLHELPSUFFIX##Cardmhz:</A></TD><TD><input name=\"cardmhz\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##CARDMHZ##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#pincode##TPLHELPSUFFIX##Pincode:</A></TD><TD><input name=\"pincode\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PINCODE##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#detect##TPLHELPSUFFIX##Detect:</A></TD><TD><input name=\"detect\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##DETECT##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#readnano##TPLHELPSUFFIX##Readnano:</A></TD><TD><input name=\"readnano\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##EMMFILE##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#blocknano##TPLHELPSUFFIX##Blocknano:</A></TD><TD><input name=\"blocknano\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##BLOCKNANO##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#savenano##TPLHELPSUFFIX##Savenano:</A></TD><TD><input name=\"savenano\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##SAVENANO##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#atr##TPLHELPSUFFIX##ATR:</A></TD><TD><input name=\"atr\" type=\"text\" size=\"100\" maxlength=\"54\" value=\"##ATR##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#boxid##TPLHELPSUFFIX##Boxid:</A></TD><TD><input name=\"boxid\" type=\"text\" size=\"15\" maxlength=\"8\" value=\"##BOXID##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#aeskeys##TPLHELPSUFFIX##AES Keys:</A></TD><TD><textarea name=\"aeskeys\" cols=\"98\" rows=\"4\" class=\"bt\" maxlength=\"128\">##AESKEYS##</textarea></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#rsakey##TPLHELPSUFFIX##RSA Key:</A></TD><TD><textarea name=\"rsakey\" cols=\"98\" rows=\"4\" class=\"bt\" maxlength=\"128\">##RSAKEY##</textarea></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#boxkey##TPLHELPSUFFIX##Boxkey:</A></TD><TD><input name=\"boxkey\" type=\"text\" size=\"20\" maxlength=\"16\" value=\"##BOXKEY##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#showcls##TPLHELPSUFFIX##Showcls:</A></TD><TD><input name=\"showcls\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SHOWCLS##\"></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#force_irdeto##TPLHELPSUFFIX##Force Irdeto:</A><input name=\"force_irdeto\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"force_irdeto\" type=\"checkbox\" value=\"1\" ##FORCEIRDETOCHECKED##></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#fix9993##TPLHELPSUFFIX##Fix 9993 for CAID 0919:</A><input name=\"fix9993\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"fix9993\" type=\"checkbox\" value=\"1\" ##FIX9993CHECKED##></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#ndsversion##TPLHELPSUFFIX##Force NDS Version:</A></TD>\n\
					<TD>\n\
						<SELECT name=\"ndsversion\">\n\
							<OPTION value=\"0\" ##NDSVERSION0##>0 - AUTO</OPTION>\n\
							<OPTION value=\"1\" ##NDSVERSION1##>1 - NDS1 Forced</OPTION>\n\
							<OPTION value=\"12\" ##NDSVERSION21##>12 - NDS1+ Forced</OPTION>\n\
							<OPTION value=\"2\" ##NDSVERSION2##>2 - NDS2 Forced</OPTION>\n\
						</SELECT>\n\
					</TD>\n\
				</TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#nagra_read##TPLHELPSUFFIX##Read Nagra Records:</A></TD>\n\
					<TD>\n\
						<SELECT name=\"nagra_read\">\n\
							<OPTION value=\"0\" ##NAGRAREAD0##>0 - Disabled</OPTION>\n\
							<OPTION value=\"1\" ##NAGRAREAD1##>1 - Read all records</OPTION>\n\
							<OPTION value=\"2\" ##NAGRAREAD2##>2 - Read only valid records</OPTION>\n\
						</SELECT>\n\
					</TD>\n\
				</TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#deprecated##TPLHELPSUFFIX##Deprecated:</A><input name=\"deprecated\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"deprecated\" type=\"checkbox\" value=\"1\" ##DEPRECATEDCHCHECKED##></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#smargopatch##TPLHELPSUFFIX##Smargopatch:</A><input name=\"smargopatch\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"smargopatch\" type=\"checkbox\" value=\"1\" ##SMARGOPATCHCHECKED##></TD></TR>\n\
				<TR><TD>##TPLHELPPREFIX##server#device_out_endpoint##TPLHELPSUFFIX##Device Out Endpoint:</A></TD><TD>##DEVICEEP##</TD></TR>\n"

#ifdef LIBUSB
#define TPLREADERCONFIGDEVICEEPBIT "\
				<SELECT name=\"device_out_endpoint\">\n\
					<OPTION value=\"\" ##DEVICEOUTEP0##>default</OPTION>\n\
					<OPTION value=\"0x82\" ##DEVICEOUTEP1##>0x82 - Smargo+</OPTION>\n\
					<OPTION value=\"0x81\" ##DEVICEOUTEP2##>0x81 - Infinity USB Smart</OPTION>\n\
				</SELECT>\n"
#endif

#define TPLREADERCONFIGCAMD35BIT "\
			<TR><TD>##TPLHELPPREFIX##server#user##TPLHELPSUFFIX##User:</A></TD><TD><input name=\"user\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#password##TPLHELPSUFFIX##Password:</A></TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#reconnecttimeout##TPLHELPSUFFIX##Reconnect timeout:</A></TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n"
#define TPLREADERCONFIGCS378XBIT "\
			<TR><TD>##TPLHELPPREFIX##server#user##TPLHELPSUFFIX##User:</A></TD><TD><input name=\"user\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#password##TPLHELPSUFFIX##Password:</A></TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#inactivitytimeout##TPLHELPSUFFIX##Inactivity timeout:</A></TD><TD><input name=\"inactivitytimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##INACTIVITYTIMEOUT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#reconnecttimeout##TPLHELPSUFFIX##Reconnect timeout:</A></TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n"
#define TPLREADERCONFIGRADEGASTBIT "\
			<TR><TD>##TPLHELPPREFIX##server#user##TPLHELPSUFFIX##User:</A></TD><TD><input name=\"user\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#password##TPLHELPSUFFIX##Password:</A></TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#inactivitytimeout##TPLHELPSUFFIX##Inactivity timeout:</A></TD><TD><input name=\"inactivitytimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##INACTIVITYTIMEOUT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#reconnecttimeout##TPLHELPSUFFIX##Reconnect timeout:</A></TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n"
#define TPLREADERCONFIGNCD525BIT "\
			<TR><TD>##TPLHELPPREFIX##server#user##TPLHELPSUFFIX##User:</A></TD><TD><input name=\"user\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#password##TPLHELPSUFFIX##Password:</A></TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#key##TPLHELPSUFFIX##Key:</A></TD><TD><input name=\"key\" type=\"text\" size=\"40\" maxlength=\"28\" value=\"##NCD_KEY##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#inactivitytimeout##TPLHELPSUFFIX##Inactivity timeout:</A></TD><TD><input name=\"inactivitytimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##INACTIVITYTIMEOUT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#reconnecttimeout##TPLHELPSUFFIX##Reconnect timeout:</A></TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#disableserverfilter##TPLHELPSUFFIX##Disable server Filter:</A><input name=\"disableserverfilter\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"disableserverfilter\" type=\"checkbox\" value=\"1\" ##DISABLESERVERFILTERCHECKED##></TD></TR>\n"
#define TPLREADERCONFIGNCD524BIT "\
			<TR><TD>##TPLHELPPREFIX##server#user##TPLHELPSUFFIX##User:</A></TD><TD><input name=\"user\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#password##TPLHELPSUFFIX##Password:</A></TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#key##TPLHELPSUFFIX##Key:</A></TD><TD><input name=\"key\" type=\"text\" size=\"40\" maxlength=\"28\" value=\"##NCD_KEY##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#inactivitytimeout##TPLHELPSUFFIX##Inactivity timeout:</A></TD><TD><input name=\"inactivitytimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##INACTIVITYTIMEOUT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#reconnecttimeout##TPLHELPSUFFIX##Reconnect timeout:</A></TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#disableserverfilter##TPLHELPSUFFIX##Disable server Filter:</A><input name=\"disableserverfilter\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"disableserverfilter\" type=\"checkbox\" value=\"1\" ##DISABLESERVERFILTERCHECKED##></TD></TR>\n"
#define TPLREADERCONFIGCCCAMBIT "\
			<TR><TD>##TPLHELPPREFIX##server#user##TPLHELPSUFFIX##User:</A></TD><TD><input name=\"user\" type=\"text\" size=\"63\" maxlength=\"63\" value=\"##ACCOUNT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#password##TPLHELPSUFFIX##Password:</A></TD><TD><input name=\"password\" type=\"text\" size=\"63\" maxlength=\"63\" value=\"##PASSWORD##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#cccversion##TPLHELPSUFFIX##Version:</A></TD>\n\
				<TD>\n\
					<SELECT name=\"cccversion\">\n\
						<OPTION value=\"2.0.11\" ##CCCVERSIONSELECTED0##>2.0.11</OPTION>\n\
						<OPTION value=\"2.1.1\"##CCCVERSIONSELECTED1##>2.1.1</OPTION>\n\
						<OPTION value=\"2.1.2\"##CCCVERSIONSELECTED2##>2.1.2</OPTION>\n\
						<OPTION value=\"2.1.3\"##CCCVERSIONSELECTED3##>2.1.3</OPTION>\n\
						<OPTION value=\"2.1.4\"##CCCVERSIONSELECTED4##>2.1.4</OPTION>\n\
						<OPTION value=\"2.2.0\"##CCCVERSIONSELECTED5##>2.2.0</OPTION>\n\
						<OPTION value=\"2.2.1\"##CCCVERSIONSELECTED6##>2.2.1</OPTION>\n\
					</SELECT>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#cccmaxhops##TPLHELPSUFFIX##Maxhop:</A></TD><TD><input name=\"cccmaxhop\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##CCCMAXHOP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#cccmindown##TPLHELPSUFFIX##Mindown:</A></TD><TD><input name=\"cccmindown\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##CCCMINDOWN##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#cccreshare##TPLHELPSUFFIX##Reshare:</A></TD><TD><input name=\"cccreshare\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##CCCRESHARE##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#cccwantemu##TPLHELPSUFFIX##Want Emu:</A><input name=\"cccwantemu\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"cccwantemu\" type=\"checkbox\" value=\"1\" ##CCCWANTEMUCHECKED##></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#reconnecttimeout##TPLHELPSUFFIX##Reconnect-timeout:</A></TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##server#ccckeepalive##TPLHELPSUFFIX##Keep alive:</A></TD><TD><SELECT NAME=\"ccckeepalive\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##KEEPALIVECHECKED##>YES</OPTION></SELECT></TD></TR>\n"

#define TPLCONFIGGBOX "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
	<DIV CLASS=\"message\">##MESSAGE##</DIV>\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"gbox\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Gbox Config </TH></TR>\n\
			<TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"10\" maxlength=\"8\" value=\"##PASSWORD##\"></TD></TR>\n\
			<TR><TD>Maxdist:</TD><TD><input name=\"maxdist\" type=\"text\" size=\"5\" maxlength=\"2\" value=\"##MAXDIST##\"></TD></TR>\n\
			<TR><TD>Ignorelist:</TD><TD><input name=\"ignorelist\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##IGNORELIST##\"></TD></TR>\n\
			<TR><TD>Onlineinfos:</TD><TD><input name=\"onlineinfos\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##ONLINEINFOS##\"></TD></TR>\n\
			<TR><TD>Cardinfos:</TD><TD><input name=\"cardinfos\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##CARDINFOS##\"></TD></TR>\n\
			<TR><TD>Locals:</TD><TD><input name=\"locals\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##LOCALS##\"></TD></TR>\n\
	    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#ifdef CS_ANTICASC
#define TPLCONFIGANTICASC "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"anticasc\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<input name=\"enabled\" type=\"hidden\" value=\"0\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Anticascading Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#enabled_2##TPLHELPSUFFIX##Enabled:</A></TD><TD><input name=\"enabled\" type=\"checkbox\" value=\"1\" ##CHECKED##>\n\
			<TR><TD>##TPLHELPPREFIX##conf#numusers##TPLHELPSUFFIX##Numusers:</A></TD><TD><input name=\"numusers\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##NUMUSERS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#sampletime##TPLHELPSUFFIX##Sampletime:</A></TD><TD><input name=\"sampletime\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SAMPLETIME##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#samples##TPLHELPSUFFIX##Samples:</A></TD><TD><input name=\"samples\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SAMPLES##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#penalty##TPLHELPSUFFIX##Penalty:</A></TD>\
			<TD>\
				<select name=\"penalty\">\n\
					<option value=\"0\" ##PENALTY0##>0 - Only write to log</option>\n\
					<option value=\"1\" ##PENALTY1##>1 - Fake DW</option>\n\
					<option value=\"2\" ##PENALTY2##>2 - Ban</option>\n\
					<option value=\"3\" ##PENALTY3##>3 - Fake DW delayed</option>\n\
				</select>\n\
			</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#aclogfile##TPLHELPSUFFIX##AClogfile:</A></TD><TD><input name=\"aclogfile\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##ACLOGFILE##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#fakedelay##TPLHELPSUFFIX##Fakedelay:</A></TD><TD><input name=\"fakedelay\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##FAKEDELAY##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#denysamples##TPLHELPSUFFIX##Denysamples:</A></TD><TD><input name=\"denysamples\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##DENYSAMPLES##\"></TD></TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"
#endif

#define TPLCONFIGCCCAM "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"cccam\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Cccam Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#port_7##TPLHELPSUFFIX##Port:</A></TD><TD><input name=\"port\" type=\"text\" size=\"6\" maxlength=\"6\" value=\"##PORT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#reshare##TPLHELPSUFFIX##Reshare:</A></TD><TD><input name=\"reshare\" type=\"text\" size=\"2\" maxlength=\"1\" value=\"##RESHARE##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#ignorereshare##TPLHELPSUFFIX##Ignore reshare:</A></TD><TD><SELECT NAME=\"ignorereshare\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##IGNORERESHARE##>ON</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#forward_origin_card##TPLHELPSUFFIX##Forward origin card:</A></TD><TD><SELECT NAME=\"forward_origin_card\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##FORWARDORIGINCARD##>ON</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#stealth##TPLHELPSUFFIX##Stealth mode:</A></TD><TD><SELECT NAME=\"stealth\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##STEALTH##>ON</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#keepconnected##TPLHELPSUFFIX##Keep clients connected:</A></TD><TD><SELECT NAME=\"keepconnected\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##KEEPCONNECTED##>ON</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#version##TPLHELPSUFFIX##Version:</A></TD>\n\
				<TD>\n\
					<SELECT name=\"version\">\n\
						<OPTION value=\"2.0.11\" ##VERSIONSELECTED0##>2.0.11</OPTION>\n\
						<OPTION value=\"2.1.1\" ##VERSIONSELECTED1##>2.1.1</OPTION>\n\
						<OPTION value=\"2.1.2\" ##VERSIONSELECTED2##>2.1.2</OPTION>\n\
						<OPTION value=\"2.1.3\" ##VERSIONSELECTED3##>2.1.3</OPTION>\n\
						<OPTION value=\"2.1.4\" ##VERSIONSELECTED4##>2.1.4</OPTION>\n\
						<OPTION value=\"2.2.0\" ##VERSIONSELECTED5##>2.2.0</OPTION>\n\
						<OPTION value=\"2.2.1\" ##VERSIONSELECTED6##>2.2.1</OPTION>\n\
					</SELECT>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#updateinterval##TPLHELPSUFFIX##Update Interval:</A></TD><TD><input name=\"updateinterval\" type=\"text\" size=\"5\" maxlength=\"4\" value=\"##UPDATEINTERVAL##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#minimizecards##TPLHELPSUFFIX##Minimize cards:</A></TD>\n\
				<TD>\n\
					<SELECT name=\"minimizecards\">\n\
						<OPTION value=\"0\" ##MINIMIZECARDSELECTED0##>0 - legacy (default)</OPTION>\n\
						<OPTION value=\"1\" ##MINIMIZECARDSELECTED1##>1 - smallest hop</OPTION>\n\
						<OPTION value=\"2\" ##MINIMIZECARDSELECTED2##>2 - via caid</OPTION>\n\
					</SELECT>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#reshare_mode##TPLHELPSUFFIX##Reshare mode:</A></TD>\n\
				<TD>\n\
					<SELECT name=\"reshare_mode\">\n\
						<OPTION value=\"0\" ##RESHAREMODE0##>0 - reshare cards only (default)</OPTION>\n\
						<OPTION value=\"1\" ##RESHAREMODE1##>1 - reshare cards+services</OPTION>\n\
						<OPTION value=\"2\" ##RESHAREMODE2##>2 - reshare reader-services</OPTION>\n\
						<OPTION value=\"3\" ##RESHAREMODE3##>3 - reshare user-services</OPTION>\n\
					</SELECT>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
	<BR><BR>\
	<TABLE class=\"config\">\n\
		<TR><TH COLSPAN=\"2\">Control</TH></TR>\n\
		<TR>\n\
			<TD STYLE=\"text-align:center;\">\
				<form action=\"config.html\" method=\"get\">\n\
				<input name=\"part\" type=\"hidden\" value=\"cccam\">\n\
				<input type=\"submit\" name=\"button\" value=\"Refresh global list\" ##BTNDISABLED##>\n\
				</form></TD>\n\
			<TD STYLE=\"text-align:center;\">\
				<form action=\"entitlements.html\" method=\"get\">\n\
				<input name=\"globallist\" type=\"hidden\" value=\"1\">\n\
				<input type=\"submit\" name=\"button\" value=\"Show global list\" ##BTNDISABLED##>\n\
				</form></TD>\n\
		</TR>\n\
	</TABLE>\n\
##TPLFOOTER##"

#define TPLCONFIGMONITOR "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"monitor\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<input name=\"httphideidleclients\" type=\"hidden\" value=\"0\">\n\
		<input name=\"appendchaninfo\" type=\"hidden\" value=\"0\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Monitor Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#port##TPLHELPSUFFIX##Port:</A></TD><TD><input name=\"port\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##MONPORT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#serverip_2##TPLHELPSUFFIX##Serverip:</A></TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#nocrypt##TPLHELPSUFFIX##No crypt:</A></TD><TD><input name=\"nocrypt\" type=\"text\" size=\"50\" maxlength=\"200\" value=\"##NOCRYPT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#aulow##TPLHELPSUFFIX##Au low:</A></TD><TD><input name=\"aulow\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##AULOW##\"> min</TD></TR>\n\
			<TR>\n\
				<TD>##TPLHELPPREFIX##conf#monlevel##TPLHELPSUFFIX##Monlevel:</A></TD>\n\
				<TD><select name=\"monlevel\">\n\
					<option value=\"0\" ##MONSELECTED0##>0 - no access to monitor</option>\n\
					<option value=\"1\" ##MONSELECTED1##>1 - only server and own procs</option>\n\
					<option value=\"2\" ##MONSELECTED2##>2 - all procs, but viewing only, default</option>\n\
					<option value=\"3\" ##MONSELECTED3##>3 - all procs, reload of oscam.user possible</option>\n\
					<option value=\"4\" ##MONSELECTED4##>4 - complete access</option>\n\
					</select>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#hideclient_to##TPLHELPSUFFIX##Hide client to:</A></TD><TD><input name=\"hideclient_to\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##HIDECLIENTTO##\"> s</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#appendchaninfo##TPLHELPSUFFIX##Append channel info:</A></TD><TD><input name=\"appendchaninfo\" type=\"checkbox\" value=\"1\" ##APPENDCHANINFO##></TD></TR>\n\
			<TR><TH COLSPAN=\"2\">Webinterface Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httpport##TPLHELPSUFFIX##Http port:</A></TD><TD><input name=\"httpport\" type=\"text\" size=\"6\" maxlength=\"6\" value=\"##HTTPPORT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httpuser##TPLHELPSUFFIX##Http user:</A></TD><TD><input name=\"httpuser\" type=\"text\" size=\"20\" maxlength=\"20\" value=\"##HTTPUSER##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httppwd##TPLHELPSUFFIX##Http pwd:</A></TD><TD><input name=\"httppwd\" type=\"text\" size=\"20\" maxlength=\"20\" value=\"##HTTPPASSWORD##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httpcss##TPLHELPSUFFIX##Http css:</A></TD>\n\
				<TD>\n\
					<SELECT name=\"httpcss\">\n\
##CSSOPTIONS##\
					</SELECT>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httphelplang##TPLHELPSUFFIX##Http Help Language (en|de|fr|it):</A></TD><TD><input name=\"httphelplang\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##HTTPHELPLANG##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httpjscript##TPLHELPSUFFIX##Http javascript:</A></TD><TD><input name=\"httpjscript\" type=\"text\" size=\"50\" maxlength=\"128\" value=\"##HTTPJSCRIPT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httprefresh##TPLHELPSUFFIX##Http refresh:</A></TD><TD><input name=\"httprefresh\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##HTTPREFRESH##\"> s</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httptpl##TPLHELPSUFFIX##Http tpl:</A></TD><TD><input name=\"httptpl\" type=\"text\" size=\"50\" maxlength=\"128\" value=\"##HTTPTPL##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httpscript##TPLHELPSUFFIX##Http script:</A></TD><TD><input name=\"httpscript\" type=\"text\" size=\"50\" maxlength=\"128\" value=\"##HTTPSCRIPT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httphideidleclients##TPLHELPSUFFIX##Http Hide Idle Clients:</A></TD><TD><input name=\"httphideidleclients\" type=\"checkbox\" value=\"1\" ##CHECKED##>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httpallowed##TPLHELPSUFFIX##Http allowed:</A></TD><TD><input name=\"httpallowed\" type=\"text\" size=\"50\" maxlength=\"200\" value=\"##HTTPALLOW##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httpdyndns##TPLHELPSUFFIX##Http dyndns:</A></TD><TD><input name=\"httpdyndns\" type=\"text\" size=\"50\" maxlength=\"200\" value=\"##HTTPDYNDNS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#httpsavefullcfg##TPLHELPSUFFIX##Http save full config:</A></TD><TD><SELECT NAME=\"httpsavefullcfg\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##HTTPSAVEFULLSELECT##>YES</OPTION></SELECT></TD></TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLCONFIGRADEGAST "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"radegast\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Radegast Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#port_6##TPLHELPSUFFIX##Port:</A></TD><TD><input name=\"port\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##PORT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#serverip_7##TPLHELPSUFFIX##Serverip:</A></TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#allowed_2##TPLHELPSUFFIX##Allowed:</A></TD><TD><input name=\"allowed\" type=\"text\" size=\"100\" maxlength=\"200\" value=\"##ALLOWED##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#user##TPLHELPSUFFIX##User:</A></TD><TD><input name=\"user\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##USER##\"></TD></TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLCONFIGNEWCAMD "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"newcamd\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<input name=\"keepalive\" type=\"hidden\" value=\"0\">\n\
		<input name=\"mgclient\" type=\"hidden\" value=\"0\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Newcamd Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#port_5##TPLHELPSUFFIX##Port:</A></TD>     <TD><textarea name=\"port\"      cols=\"120\" rows=\"3\" class=\"bt\">##PORT##</textarea></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#serverip_6##TPLHELPSUFFIX##Serverip:</A></TD><TD><input name=\"serverip\" type=\"text\" size=\"60\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#key_2##TPLHELPSUFFIX##Key:</A></TD><TD><input name=\"key\" type=\"text\" size=\"60\" maxlength=\"28\" value=\"##KEY##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#allowed##TPLHELPSUFFIX##Allowed:</A></TD>     <TD><textarea name=\"allowed\"      cols=\"58\" rows=\"3\" class=\"bt\">##ALLOWED##</textarea></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#keepalive##TPLHELPSUFFIX##Keepalive:</A></TD><TD><input name=\"keepalive\" type=\"checkbox\" value=\"1\" ##KEEPALIVE##></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#mgclient##TPLHELPSUFFIX##Mgclient:</A></TD><TD><input name=\"mgclient\" type=\"checkbox\" value=\"1\" ##MGCLIENTCHK##></TD></TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLCONFIGGLOBAL "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"global\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<input name=\"suppresscmd08\" type=\"hidden\" value=\"0\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Global Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#serverip##TPLHELPSUFFIX##Serverip:</A></TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#nice##TPLHELPSUFFIX##Nice:</A></TD><TD><input name=\"nice\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##NICE##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#netprio##TPLHELPSUFFIX##Net prio:</A></TD><TD><input name=\"netprio\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##NETPRIO##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#bindwait##TPLHELPSUFFIX##Bind wait:</A></TD><TD><input name=\"bindwait\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##BINDWAIT##\"> s</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#resolvegethostbyname##TPLHELPSUFFIX##Resolver:</A></TD>\n\
				<TD>\n\
					<select name=\"resolvegethostbyname\">\n\
						<option value=\"0\" ##RESOLVER0##>0 - getadressinfo()</option>\n\
						<option value=\"1\" ##RESOLVER1##>1 - gethostbyname()</option>\n\
					</select>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#waitforcards##TPLHELPSUFFIX##Wait for cards:</A></TD><TD><SELECT NAME=\"waitforcards\"><OPTION VALUE=\"0\">0 - enable clientlogins while init</OPTION><OPTION VALUE=\"1\" ##WAITFORCARDSCHECKED##>1 - disable clientlogins while init</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#waitforcards_extra_delay##TPLHELPSUFFIX##Extra delay:</A></TD><TD><input name=\"waitforcards_extra_delay\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##EXTRADELAY##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#preferlocalcards##TPLHELPSUFFIX##Prefer local cards:</A></TD><TD><SELECT NAME=\"preferlocalcards\"><OPTION VALUE=\"0\">0 - local cards like proxied</OPTION><OPTION VALUE=\"1\" ##PREFERLOCALCARDSCHECKED##>1 - prefer local cards</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#unlockparental##TPLHELPSUFFIX##Unlock parental:</A></TD><TD><SELECT NAME=\"unlockparental\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##UNLOCKPARENTALCHECKED##>YES</OPTION></SELECT></TD></TR>\n\
			<TR><TH COLSPAN=\"2\">Logging</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#disableuserfile##TPLHELPSUFFIX##Usr file:</A></TD>\n\
				<TD>\n\
					<input name=\"usrfile\" type=\"text\" size=\"30\" maxlength=\"128\" value=\"##USERFILE##\">&nbsp;\n\
					<SELECT NAME=\"disableuserfile\"><OPTION VALUE=\"0\">0 - enabled</OPTION><OPTION VALUE=\"1\" ##DISABLEUSERFILECHECKED##>1 - disabled</OPTION></SELECT>&nbsp;\n\
					<SELECT NAME=\"usrfileflag\"><OPTION VALUE=\"0\">0 - just join/leave</OPTION><OPTION VALUE=\"1\" ##USERFILEFLAGCHECKED##>1 - each zap</OPTION></SELECT>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#logfile##TPLHELPSUFFIX##Log file / max size:</A></TD>\n\
				<TD>\n\
					<input name=\"logfile\" type=\"text\" size=\"30\" maxlength=\"128\" value=\"##LOGFILE##\">&nbsp;\n\
					<SELECT NAME=\"disablelog\"><OPTION VALUE=\"0\">0 - enabled</OPTION><OPTION VALUE=\"1\" ##DISABLELOGCHECKED##>1 - disabled</OPTION></SELECT>&nbsp;\n\
					<input name=\"maxlogsize\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##MAXLOGSIZE##\"> kB\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#cwlogdir##TPLHELPSUFFIX##CW log dir:</A></TD><TD><input name=\"cwlogdir\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##CWLOGDIR##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#saveinithistory##TPLHELPSUFFIX##Reader entitlements:</A></TD><TD><SELECT NAME=\"saveinithistory\"><OPTION VALUE=\"0\">0 - dismiss entitlements</OPTION><OPTION VALUE=\"1\" ##SAVEINITHISTORYCHECKED##>1 - save entitlements</OPTION></SELECT></TD></TR>\n\
			<TR><TH COLSPAN=\"2\">Failban</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#failbantime##TPLHELPSUFFIX##Failban time:</A></TD><TD><input name=\"failbantime\" type=\"text\" size=\"5\" maxlength=\"6\" value=\"##FAILBANTIME##\"> min blocking IP based</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#failbancount##TPLHELPSUFFIX##Failban count:</A></TD><TD><input name=\"failbancount\" type=\"text\" size=\"5\" maxlength=\"2\" value=\"##FAILBANCOUNT##\"> chances with wrong credenticals</TD></TR>\n\
			<TR><TH COLSPAN=\"2\">Timeouts / Times</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#clienttimeout##TPLHELPSUFFIX##Client timeout:</A></TD><TD><input name=\"clienttimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##CLIENTTIMEOUT##\"> ms to give up and return timeout</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#fallbacktimeout##TPLHELPSUFFIX##Fallback timeout:</A></TD><TD><input name=\"fallbacktimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##FALLBACKTIMEOUT##\"> ms to switch to fallback reader</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#cachedelay##TPLHELPSUFFIX##Cache delay:</A></TD><TD><input name=\"cachedelay\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##CACHEDELAY##\"> ms delaying answers from cache</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#clientmaxidle##TPLHELPSUFFIX##Client max idle:</A></TD><TD><input name=\"clientmaxidle\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##CLIENTMAXIDLE##\"> s to disconnect idle clients</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#sleep##TPLHELPSUFFIX##Global sleep:</A></TD><TD><input name=\"sleep\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SLEEP##\"> min to switch a client in sleepmode</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#suppresscmd08##TPLHELPSUFFIX##Suppress cmd08:</A></TD><TD><input name=\"suppresscmd08\" type=\"checkbox\" value=\"1\" ##SUPPRESSCMD08##></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#serialreadertimeout##TPLHELPSUFFIX##Serial reader timeout:</A></TD><TD><input name=\"serialreadertimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SERIALTIMEOUT##\"> ms</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#readerrestartseconds##TPLHELPSUFFIX##Reader restart seconds:</A></TD><TD><input name=\"readerrestartseconds\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##READERRESTARTSECONDS##\"> s waittime to restart a reader</TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#dropdups##TPLHELPSUFFIX##Drop duplicate users:</A></TD><TD><SELECT NAME=\"dropdups\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##DROPDUPSCHECKED##>YES</OPTION></SELECT></TD></TR>\n\
##TPLDOUBLECHECKBIT##\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#ifdef CS_WITH_DOUBLECHECK
#define TPLDOUBLECHECKBIT "\
			<TR><TD>##TPLHELPPREFIX##conf#double_check##TPLHELPSUFFIX##ECM Doublecheck:</A></TD><TD><SELECT NAME=\"double_check\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##DCHECKCSELECTED##>YES</OPTION></SELECT></TD></TR>\n"
#endif

#define TPLCONFIGLOADBALANCER "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"loadbalancer\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Loadbalancer Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_mode##TPLHELPSUFFIX##Loadbalance Mode:</A></TD>\n\
				<TD>\n\
					<select name=\"lb_mode\">\n\
						<option value=\"0\" ##LBMODE0##>0 - Loadbalancer disabled (send to all readers)</option>\n\
						<option value=\"1\" ##LBMODE1##>1 - Fastest reader first</option>\n\
						<option value=\"2\" ##LBMODE2##>2 - Oldest reader first</option>\n\
						<option value=\"3\" ##LBMODE3##>3 - Lowest usagelevel</option>\n\
						<option value=\"10\" ##LBMODE10##>10 - Log statistics only</option>\n\
					</select>\n\
				</TD>\n\
			</TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_save##TPLHELPSUFFIX##Loadbalance save every:</A></TD><TD><input name=\"lb_save\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBSAVE##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_savepath##TPLHELPSUFFIX##Statistics save path:</A></TD><TD><input name=\"lb_savepath\" type=\"text\" size=\"50\" maxlength=\"255\" value=\"##LBSAVEPATH##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_nbest_readers##TPLHELPSUFFIX##Number of best readers:</A></TD><TD><input name=\"lb_nbest_readers\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBNBESTREADERS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_nbest_percaid##TPLHELPSUFFIX##Number of best readers per caid:</A></TD><TD><input name=\"lb_nbest_percaid\" type=\"text\" size=\"50\" maxlength=\"255\" value=\"##LBNBESTPERCAID##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_nfb_readers##TPLHELPSUFFIX##Number of fallback readers:</A></TD><TD><input name=\"lb_nfb_readers\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBNFBREADERS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_min_ecmcount##TPLHELPSUFFIX##Min ECM count:</A></TD><TD><input name=\"lb_min_ecmcount\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBMINECMCOUNT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_max_ecmcount##TPLHELPSUFFIX##Max ECM count:</A></TD><TD><input name=\"lb_max_ecmcount\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBMAXECEMCOUNT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_retrylimit##TPLHELPSUFFIX##Retry limit:</A></TD><TD><input name=\"lb_retrylimit\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBRETRYLIMIT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_retrylimits##TPLHELPSUFFIX##Special retry limit per caid:</A></TD><TD><input name=\"lb_retrylimits\" type=\"text\" size=\"50\" maxlength=\"255\" value=\"##LBRETRYLIMITS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_reopen_seconds##TPLHELPSUFFIX##Time to reopen:</A></TD><TD><input name=\"lb_reopen_seconds\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBREOPENSECONDS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_stat_cleanup##TPLHELPSUFFIX##Hours to cleanup older than:</A></TD><TD><input name=\"lb_stat_cleanup\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBCLEANUP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_use_locking##TPLHELPSUFFIX##Use locking:</A></TD><TD><SELECT NAME=\"lb_use_locking\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##USELOCKINGCHECKED##>YES</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_reopen_mode##TPLHELPSUFFIX##Reopen mode:</A></TD><TD><SELECT NAME=\"lb_reopen_mode\"><OPTION VALUE=\"0\">0 - reopen after time</OPTION><OPTION VALUE=\"1\" ##REOPENMODE##>1 - reopen fast</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#lb_noproviderforcaid##TPLHELPSUFFIX##Ignore provider for:</A></TD><TD><input name=\"lb_noproviderforcaid\" type=\"text\" size=\"50\" maxlength=\"255\" value=\"##LBNOPROVIDERFORCAID##\"></TD></TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
	<BR><BR>\
	<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"loadbalancer\">\n\
	<TABLE class=\"config\">\n\
		<TR><TH COLSPAN=\"3\">Control</TH></TR>\n\
		<TR>\n\
			<TD STYLE=\"text-align:center;\"><input type=\"submit\" name=\"button\" value=\"Load Stats\" ##BTNDISABLED##></TD>\n\
			<TD STYLE=\"text-align:center;\"><input type=\"submit\" name=\"button\" value=\"Save Stats\" ##BTNDISABLED##></TD>\n\
			<TD STYLE=\"text-align:center;\"><input type=\"submit\" name=\"button\" value=\"Clear Stats\" ##BTNDISABLED##></TD>\n\
		</TR>\n\
	</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLCONFIGCAMD33 "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"camd33\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<TABLE CLASS=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Camd33 Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#port_2##TPLHELPSUFFIX##Port:</A></TD><TD><input name=\"port\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##PORT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#serverip_3##TPLHELPSUFFIX##Serverip:</A></TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#key##TPLHELPSUFFIX##Key:</A></TD><TD><input name=\"key\" type=\"text\" size=\"41\" maxlength=\"32\" value=\"##KEY##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#passive##TPLHELPSUFFIX##Passive:</A></TD><TD><SELECT NAME=\"passive\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##PASSIVECHECKED##>YES</OPTION></SELECT></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#nocrypt_2##TPLHELPSUFFIX##Nocrypt:</A></TD><TD><input name=\"nocrypt\" type=\"text\" size=\"100\" maxlength=\"200\" value=\"##NOCRYPT##\"></TD></TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLCONFIGCAMD35 "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"camd35\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<input name=\"suppresscmd08\" type=\"hidden\" value=\"0\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Camd35 Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#port_3##TPLHELPSUFFIX##Port:</A></TD><TD><input name=\"port\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##PORT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#serverip_4##TPLHELPSUFFIX##Serverip:</A></TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#suppresscmd08##TPLHELPSUFFIX##Suppress cmd08:</A></TD><TD><input name=\"suppresscmd08\" type=\"checkbox\" value=\"1\" ##SUPPRESSCMD08UDP##></TD></TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLCONFIGCAMD35TCP "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"camd35tcp\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<input name=\"suppresscmd08\" type=\"hidden\" value=\"0\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Camd35 TCP Config</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#port_4##TPLHELPSUFFIX##Port:</A></TD><TD><input name=\"port\" type=\"text\" size=\"50\" maxlength=\"100\" value=\"##PORT##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#serverip_5##TPLHELPSUFFIX##Serverip:</A></TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##conf#suppresscmd08##TPLHELPSUFFIX##Suppress cmd08:</A></TD><TD><input name=\"suppresscmd08\" type=\"checkbox\" value=\"1\" ##SUPPRESSCMD08TCP##></TD></TR>\n\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLCONFIGSERIAL "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
	<BR><BR>\n\
##MESSAGE##\
	<form action=\"config.html\" method=\"get\">\n\
		<input name=\"part\" type=\"hidden\" value=\"serial\">\n\
		<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
		<TABLE class=\"config\">\n\
			<TR><TH COLSPAN=\"2\">Edit Serial Config</TH></TR>\n\
##DEVICES##\
			<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
		</TABLE>\n\
	</form>\n\
	<BR><BR>\n\
##TPLFOOTER##"

#define TPLCONFIGSERIALDEVICEBIT "\
			<TR><TD>##TPLHELPPREFIX##conf#device##TPLHELPSUFFIX##Device:</A></TD><TD><input name=\"device\" type=\"text\" size=\"50\" maxlength=\"100\" value=\"##SERIALDEVICE##\"></TD></TR>\n"

#ifdef HAVE_DVBAPI
#define TPLCONFIGDVBAPI "\
##TPLHEADER##\
##TPLMENU##\
##TPLCONFIGMENU##\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"dvbapi\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<input name=\"enabled\" type=\"hidden\" value=\"0\">\n\
	<input name=\"au\" type=\"hidden\" value=\"0\">\n\
	<TABLE class=\"config\">\n\
		<TR><TH COLSPAN=\"2\">Edit DVB Api Config</TH></TR>\n\
		<TR><TD>##TPLHELPPREFIX##conf#enabled##TPLHELPSUFFIX##Enabled:</A></TD><TD><input name=\"enabled\" type=\"checkbox\" value=\"1\" ##ENABLEDCHECKED##>\n\
		<TR><TD>##TPLHELPPREFIX##conf#au##TPLHELPSUFFIX##AU:</A></TD><TD><input name=\"au\" type=\"checkbox\" value=\"1\" ##AUCHECKED##>\n\
		<TR><TD>##TPLHELPPREFIX##conf#boxtype##TPLHELPSUFFIX##Boxtype:</A></TD><TD><SELECT name=\"boxtype\">##BOXTYPE##</select></TD></TR>\n\
		<TR><TD>##TPLHELPPREFIX##conf#user_2##TPLHELPSUFFIX##User:</A></TD><TD><input name=\"user\" type=\"text\" size=\"20\" maxlength=\"20\" value=\"##USER##\"></TD></TR>\n\
		<TR><TD>##TPLHELPPREFIX##conf#pmt_mode##TPLHELPSUFFIX##PMT Mode:</A></TD><TD><select name=\"pmt_mode\">\n\
			<option value=\"0\" ##PMTMODESELECTED0##>0 - use camd.socket and PMT file</option>\n\
			<option value=\"1\" ##PMTMODESELECTED1##>1 - disable reading PMT file</option>\n\
			<option value=\"2\" ##PMTMODESELECTED2##>2 - disable camd.socket</option>\n\
			<option value=\"3\" ##PMTMODESELECTED3##>3 - read PMT file on startup only</option>\n\
			<option value=\"4\" ##PMTMODESELECTED4##>4 - do not use signal handler to monitor /tmp</option>\n\
			<option value=\"5\" ##PMTMODESELECTED5##>5 - do not use signal handler to monitor /tmp & disable camd.socket</option>\n\
		</SELECT></TD></TR>\n\
		<TR><TD>##TPLHELPPREFIX##conf#request_mode##TPLHELPSUFFIX##Request Mode:</A></TD><TD><select name=\"request_mode\">\n\
			<option value=\"0\" ##REQMODESELECTED0##>0 - try all possible CAIDs one by one</option>\n\
			<option value=\"1\" ##REQMODESELECTED1##>1 - try all CAIDs simultaneously</option>\n\
		</SELECT></TD></TR>\n\
    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"Save\" ##BTNDISABLED##></TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"
#endif

#define TPLSERVICECONFIGLIST "\
##TPLHEADER##\
##TPLMENU##\
##MESSAGE##\
	<BR><BR>\n\
	<TABLE CLASS=\"stats\">\n\
		<TR>\n\
			<TH>Label</TH>\n\
			<TH colspan=\"3\" align=\"center\">Action</TH>\n\
		</TR>\n\
##SERVICETABS##\
		<TR>\n\
			<FORM action=\"services_edit.html\" method=\"get\"><INPUT TYPE=\"hidden\" NAME=\"action\" VALUE=\"add\">\n\
				<TD>New Service:</TD>\n\
				<TD><input name=\"service\" type=\"text\"></TD>\n\
				<TD colspan=\"2\" align=\"center\"><input type=\"submit\" value=\"Add\" ##BTNDISABLED##></TD>\n\
			</FORM>\n\
		<TR>\n\
	</TABLE>\n\
##TPLFOOTER##"

#define TPLSERVICECONFIGLISTBIT "\
		<TR>\n\
			<TD>##LABEL##</TD>\n\
			<TD width=\"250\" align=\"center\">\n\
##SIDLIST##\
			</TD>\n\
			<TD><A HREF=\"services_edit.html?service=##LABELENC##&action=edit\" TITLE=\"Edit this Service\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICEDI\" BORDER=\"0\" ALT=\"Edit Service\"/></A></TD>\n\
			<TD><A HREF=\"services.html?service=##LABELENC##&action=delete\" TITLE=\"Delete this Service\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICDEL\" BORDER=\"0\" ALT=\"Delete Service\"/></A></TD>\n\
		</TR>\n"

#define TPLSERVICECONFIGSIDBIT "				<DIV class=\"##SIDCLASS##\">##SID##</DIV>\n"

#define TPLSERVICEEDIT "\
##TPLHEADER##\
##TPLMENU##\
##MESSAGE##\
	<BR><BR>\n\
	<form action=\"services_edit.html\" method=\"get\">\n\
		<input name=\"service\" type=\"hidden\" value=\"##LABELENC##\">\n\
		<TABLE CLASS=\"stats\">\n\
			<TR><TH COLSPAN=\"2\">Edit Service ##LABEL##</TH></TR>\n\
			<TR><TD>##TPLHELPPREFIX##services#caid##TPLHELPSUFFIX##caid: </A></TD><TD><input name=\"caid\" type=\"text\" size=\"63\" maxlength=\"63\" value=\"##CAIDS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##services#provid##TPLHELPSUFFIX##provid: </A></TD><TD><input name=\"provid\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##PROVIDS##\"></TD></TR>\n\
			<TR><TD>##TPLHELPPREFIX##services#srvid##TPLHELPSUFFIX##srvid: </A></TD><TD><textarea name=\"srvid\" cols=\"80\" rows=\"5\">##SRVIDS##</textarea></TD></TR>\n\
			<TR><TD>&nbsp;</TD><TD align=\"right\"><input type=\"submit\" name=\"action\" value=\"Save\" title=\"Save service and reload services\" ##BTNDISABLED##></TD>\n\
		</TABLE>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLPRESHUTDOWN "\
##TPLHEADER##\
##TPLMENU##\
	<br><br><br>\n\
	<DIV class = \"warning\">Do you really want to shutdown&#47; restart oscam?<br>All users will become disconnected.<br>\n\
		If you use &#39;Shutdown&#39; you will not be able to restart oscam from webinterface.<br>\n\
		The webinterface will try to connect to oscam once a few seconds after shutdown&#47; restart.</b><br>\n\
	</DIV>\n\
	<br>\n\
	<form action=\"shutdown.html\" method=\"get\">\n\
		<input type=\"submit\" name=\"action\" value=\"Shutdown\" title=\"Shutdown Oscam\" ##BTNDISABLED##>\n\
		<input type=\"submit\" name=\"action\" value=\"Restart\" title=\"Restart Oscam\" ##BTNDISABLED##>\n\
	</form>\n\
##TPLFOOTER##"

#define TPLSHUTDOWN "\
<HTML>\n\
<HEAD>\n\
	<TITLE>OSCAM ##CS_VERSION## build ###CS_SVN_VERSION##</TITLE>\n\
	<link href=\"favicon.ico\" rel=\"icon\" type=\"image/x-icon\"/>\
##REFRESH##\
	<style type=\"text/css\">\n\
##STYLESHEET##\n\
	</style>\n\
</HEAD>\n\
<BODY>\n\
	<H2>OSCAM ##CS_VERSION## build ###CS_SVN_VERSION##</H2>\
##TPLMENU##\
	<br><P CLASS=\"blinking\">Oscam Shutdown - Try Reconnect in ##SECONDS## Seconds</p><br><br>\n\
##TPLFOOTER##"

#define TPLSCRIPT "\
##TPLHEADER##\
##TPLMENU##\
##MESSAGE##\
	<br><br><b>Oscam execute script: ##SCRIPTNAME## --> Status: ##SCRIPTRESULT## --> Returncode: ##CODE##</b><br>\n\
##TPLFOOTER##"

enum refreshtypes {REFR_ACCOUNTS, REFR_READERS, REFR_SERVER, REFR_ANTICASC, REFR_SERVICES};

char *tpl[]={
	"HEADER",
	"APIHEADER",
	"APIERROR",
	"APICONFIRMATION",
	"FOOTER",
	"APIFOOTER",
	"MENU",
	"REFRESH",
	"HELPPREFIX",
	"HELPSUFFIX",
	"STATUS",
	"APISTATUS",
	"CLIENTSTATUSBIT",
	"APISTATUSBIT",
	"USERCONFIGLIST",
	"ADDNEWUSER",
	"USERCONFIGLISTBIT",
	"APIUSERCONFIGLIST",
	"APIUSERCONFIGLISTBIT",
	"SIDTAB",
	"SIDTABBIT",
	"READERS",
	"READERSBIT",
	"READERENTITLEBIT",
	"READERREFRESHBIT",
	"READERSTATS",
	"READERSTATSBIT",
	"SCANUSB",
	"SCANUSBBIT",
	"ENTITLEMENTS",
	"ENTITLEMENTGENERICBIT",
	"ENTITLEMENTCCCAMBIT",
	"ENTITLEMENTCCCAMENTRYBIT",
	"APICCCAMCARDLIST",
	"APICCCAMCARDBIT",
	"APICCCAMCARDNODEBIT",
	"APICCCAMCARDPROVIDERBIT",
	"APIREADERSTATS",
	"APIREADERSTATSEMMBIT",
	"APIREADERSTATSECMBIT",
	"READERCONFIG",
	"READERCONFIGSIDOKBIT",
	"READERCONFIGSIDNOBIT",
	"READERCONFIGSTDHWREADERBIT",
	"READERCONFIGCAMD35BIT",
	"READERCONFIGCS378XBIT",
	"READERCONFIGRADEGASTBIT",
	"READERCONFIGNCD525BIT",
	"READERCONFIGNCD524BIT",
	"READERCONFIGCCCAMBIT",
	"USEREDIT",
	"USEREDITRDRSELECTED",
	"USEREDITSIDOKBIT",
	"USEREDITSIDNOBIT",
	"SAVETEMPLATES",
	"CONFIGMENU",
	"FILEMENU",
	"FILE",
	"FAILBAN",
	"FAILBANBIT",
	"CONFIGGBOX",
	"CONFIGCCCAM",
	"CONFIGMONITOR",
	"CONFIGRADEGAST",
	"CONFIGNEWCAMD",
	"CONFIGGLOBAL",
	"CONFIGLOADBALANCER",
	"CONFIGCAMD33",
	"CONFIGCAMD35",
	"CONFIGCAMD35TCP",
	"CONFIGSERIAL",
	"CONFIGSERIALDEVICEBIT",
	"SERVICECONFIGLIST",
	"SERVICECONFIGLISTBIT",
	"SERVICECONFIGSIDBIT",
	"SERVICEEDIT",
	"PRESHUTDOWN",
	"SHUTDOWN",
	"SCRIPT"
#ifdef HAVE_DVBAPI
	,"CONFIGDVBAPI"
	,"CONFIGMENUDVBAPI"
	,"FILEMENUDVBAPI"
#endif
#ifdef CS_ANTICASC
	,"USEREDITANTICASC"
	,"CONFIGANTICASC"
	,"CONFIGMENUANTICASC"
	,"FILEMENUANTICASC"
#endif
#ifdef CS_WITH_DOUBLECHECK
	,"DOUBLECHECKBIT"
#endif
#ifdef LIBUSB
	,"READERCONFIGDEVICEEPBIT"
#endif
#ifdef WITH_DEBUG
	,"DEBUGSELECT"
#endif
	,"ICMAI"
	,"ICSTA"
	,"ICDEL"
	,"ICEDI"
	,"ICENT"
	,"ICREF"
	,"ICKIL"
	,"ICDIS"
	,"ICENA"
	,"ICHID"
	,"ICRES"
};

char *tplmap[]={
	TPLHEADER,
	TPLAPIHEADER,
	TPLAPIERROR,
	TPLAPICONFIRMATION,
	TPLFOOTER,
	TPLAPIFOOTER,
	TPLMENU,
	TPLREFRESH,
	TPLHELPPREFIX,
	TPLHELPSUFFIX,
	TPLSTATUS,
	TPLAPISTATUS,
	TPLCLIENTSTATUSBIT,
	TPLAPISTATUSBIT,
	TPLUSERCONFIGLIST,
	TPLADDNEWUSER,
	TPLUSERCONFIGLISTBIT,
	TPLAPIUSERCONFIGLIST,
	TPLAPIUSERCONFIGLISTBIT,
	TPLSIDTAB,
	TPLSIDTABBIT,
	TPLREADERS,
	TPLREADERSBIT,
	TPLREADERENTITLEBIT,
	TPLREADERREFRESHBIT,
	TPLREADERSTATS,
	TPLREADERSTATSBIT,
	TPLSCANUSB,
	TPLSCANUSBBIT,
	TPLENTITLEMENTS,
	TPLENTITLEMENTGENERICBIT,
	TPLENTITLEMENTCCCAMBIT,
	TPLENTITLEMENTCCCAMENTRYBIT,
	TPLAPICCCAMCARDLIST,
	TPLAPICCCAMCARDBIT,
	TPLAPICCCAMCARDNODEBIT,
	TPLAPICCCAMCARDPROVIDERBIT,
	TPLAPIREADERSTATS,
	TPLAPIREADERSTATSEMMBIT,
	TPLAPIREADERSTATSECMBIT,
	TPLREADERCONFIG,
	TPLREADERCONFIGSIDOKBIT,
	TPLREADERCONFIGSIDNOBIT,
	TPLREADERCONFIGSTDHWREADERBIT,
	TPLREADERCONFIGCAMD35BIT,
	TPLREADERCONFIGCS378XBIT,
	TPLREADERCONFIGRADEGASTBIT,
	TPLREADERCONFIGNCD525BIT,
	TPLREADERCONFIGNCD524BIT,
	TPLREADERCONFIGCCCAMBIT,
	TPLUSEREDIT,
	TPLUSEREDITRDRSELECTED,
	TPLUSEREDITSIDOKBIT,
	TPLUSEREDITSIDNOBIT,
	TPLSAVETEMPLATES,
	TPLCONFIGMENU,
	TPLFILEMENU,
	TPLFILE,
	TPLFAILBAN,
	TPLFAILBANBIT,
	TPLCONFIGGBOX,
	TPLCONFIGCCCAM,
	TPLCONFIGMONITOR,
	TPLCONFIGRADEGAST,
	TPLCONFIGNEWCAMD,
	TPLCONFIGGLOBAL,
	TPLCONFIGLOADBALANCER,
	TPLCONFIGCAMD33,
	TPLCONFIGCAMD35,
	TPLCONFIGCAMD35TCP,
	TPLCONFIGSERIAL,
	TPLCONFIGSERIALDEVICEBIT,
	TPLSERVICECONFIGLIST,
	TPLSERVICECONFIGLISTBIT,
	TPLSERVICECONFIGSIDBIT,
	TPLSERVICEEDIT,
	TPLPRESHUTDOWN,
	TPLSHUTDOWN,
	TPLSCRIPT
#ifdef HAVE_DVBAPI
	,TPLCONFIGDVBAPI
	,TPLCONFIGMENUDVBAPI
	,TPLFILEMENUDVBAPI
#endif
#ifdef CS_ANTICASC
	,TPLUSEREDITANTICASC
	,TPLCONFIGANTICASC
	,TPLCONFIGMENUANTICASC
	,TPLFILEMENUANTICASC
#endif
#ifdef CS_WITH_DOUBLECHECK
	,TPLDOUBLECHECKBIT
#endif
#ifdef LIBUSB
	,TPLREADERCONFIGDEVICEEPBIT
#endif
#ifdef WITH_DEBUG
	,TPLDEBUGSELECT
#endif
	,ICMAI
	,ICSTA
	,ICDEL
	,ICEDI
	,ICENT
	,ICREF
	,ICKIL
	,ICDIS
	,ICENA
	,ICHID
	,ICRES
};

struct templatevars {
	uint varscnt;
	uint varsalloc;
	uint tmpcnt;
	uint tmpalloc;
	char **names;
	char **values;
	uint8 *vartypes;
	char **tmp;
};

struct uriparams {
	int paramcount;
	char *params[MAXGETPARAMS];
	char *values[MAXGETPARAMS];
};

static char noncekey[33];

int cv(){return 91789605==crc32(0L,(unsigned char*)ICMAI,strlen(ICMAI))/2?1:0;}

