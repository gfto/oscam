
#define SERVER "webserver/1.0"
#define PROTOCOL "HTTP/1.0"
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"
#define AUTHREALM "Forbidden"
#define AUTHNONCEVALIDSECS 15
#define MAXGETPARAMS 100
#define SHUTDOWNREFRESH 30

#define CSS "\
body {background-color: white; font-family: Arial; font-size: 11px; text-align:center}\n\
p {color: white; }\n\
h2 {color: #F7F7F7; font-family: Arial; font-size: 50px; line-height: 50px; text-align:center; margin-top:0px; margin-bottom:0px}\n\
h4 {color: #AAAAAA; font-family: Arial; font-size: 12px; line-height: 9px; text-align:center}\n\
TABLE {border-spacing:1px; border:0px; padding:0px; margin-left:auto; margin-right:auto;}\n\
TH {height:10px; border:0px; font-family: Arial; font-size: 11px; padding:5px; background-color:#CCCCCC; color:black;}\n\
TD {height:10px; border:0px; font-family: Arial; font-size: 11px; padding:5px; background-color:#EEEEEE; color:black;}\n\
HR {height:1px; border-width:0; color:white; background-color:#AAAAAA}\n\
TR.s TD {background-color:#e1e1ef;}\n\
TR.l TD {background-color:#e1e1ef;}\n\
TR.n TD {background-color:#e1e1ef;}\n\
TR.h TD {background-color:#e1e1ef;}\n\
TR.r TD {background-color:#fff3e7;}\n\
TR.p TD {background-color:#fdfbe1;}\n\
TR.c TD {background-color:#f1f5e6;}\n\
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
input{font-family: Arial; font-size: 12px;}\n\
A:link {color: #050840;}\n\
A:visited {color: #050840;}\n\
A:active {color: #050840;}\n\
A:hover {color: #ff9e5f;}\n\
DIV.message {float:right}\n\
IMG{border:0px solid;}\n\
P.blinking {text-decoration: blink; font-weight:bold; font-size:large; color:red;}\n\
H4.styleauthor:after {content:\"Eneen\";}\n"

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

#define TPLHEADER "\
		<HTML>\n\
		<HEAD>\n\
		<TITLE>OSCAM ##CS_VERSION## build ###CS_SVN_VERSION##</TITLE>\n\
		<link rel=\"stylesheet\" type=\"text/css\" href=\"site.css\">\n\
		<link href=\"##ICO##\" rel=\"icon\" type=\"image/x-icon\"/>\
		##REFRESH##\
		</HEAD>\n\
		<BODY>\n\
		<H2>OSCAM ##CS_VERSION## build ###CS_SVN_VERSION##</H2>"

#define TPLFOOTER "\
		<HR/><H4>OSCAM Webinterface developed by Streamboard Team - ##CURDATE## ##CURTIME## | Access from ##CURIP##</H4><H4>Start: ##STARTDATE## - ##STARTTIME## | UpTime: ##UPTIME## </H4><H4 CLASS=\"styleauthor\">WebIf Style by </H4>\
		</BODY>\
		</HTML>"

#define TPLREFRESH "\
		\n<meta http-equiv=\"refresh\" content=\"##REFRESHTIME##; URL=##REFRESHURL##\" />\n"

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
		</TABLE>"

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
		</TABLE>"

#define TPLFILEMENU "\
	<BR><BR>\n\
	<TABLE border=0 class=\"configmenu\">\n\
		<TR>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=version\">oscam.version</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=conf\">oscam.conf</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=user\">oscam.user</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=server\">oscam.server</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=services\">oscam.services</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=srvid\">oscam.srvid</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=provid\">oscam.provid</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=logfile\">logfile</TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=userfile\">userfile</TD>\n\
			##TPLFILEMENUANTICASC##\
		</TR>\n\
	</TABLE>"

#define TPLFILE "\
  ##TPLHEADER##\
  ##TPLMENU##\n\
  ##TPLFILEMENU##\n\
  <BR><BR>##SDEBUG####SLOG####SCLEAR##<BR>##FILTER##\n\
  <DIV class=\"log\">\
  <pre>##FILECONTENT##</pre>\
  </DIV><BR>\n\
  ##TPLFOOTER##"

#define TPLFAILBAN "\
##TPLHEADER##\
##TPLMENU##\n\
	<BR><BR>\n\
	<BR><BR>\n\
	<TABLE cellspacing=\"0\" cellpadding=\"10\">\n\
	<TR><TH colspan=\"4\">List of banned IP Addresses</TH></TR>\n\
	<TR><TH>IP Address</TH><TH>Violation date</TH><TH>left ban time (min)</TH><TH>Action</TH></TR>\n\
    ##FAILBANROW##\n\
	</TABLE><BR>\n\
##TPLFOOTER##"

#define TPLFAILBANBIT "\
	<TR><TD>##IPADDRESS##</TD>\
	<TD>##VIOLATIONDATE##</TD>\
	<TD align=\"center\">##LEFTTIME##</TD>\
	<TD align=\"center\"><A HREF=\"failban.html?action=delete&intip=##INTIP##\" TITLE=\"Delete Entry\"><IMG SRC=\"##DELICO##\" BORDER=\"0\" ALT=\"Delete Entry\"/></A></TD></TR>\n"

#ifdef CS_ANTICASC
#define TPLCONFIGMENUANTICASC "<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=anticasc\">Anticascading</A></TD>\n"
#define TPLFILEMENUANTICASC "<TD CLASS=\"configmenu\"><A HREF=\"files.html?part=anticasc\">AC Log</A></TD>\n"
#endif

#ifdef HAVE_DVBAPI
#define TPLCONFIGMENUDVBAPI "<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=dvbapi\">DVB-Api</A></TD>\n"
#endif

#ifdef CS_WITH_GBOX
#define TPLCONFIGMENUGBOX "<TD CLASS=\"configmenu\"><A HREF=\"config.html?part=gbox\">Gbox</A></TD>\n"
#endif

#define TPLSTATUS "\
		##TPLHEADER##\
		##TPLMENU##\n\
		<BR><BR>\n\
		<form action=\"status.html\" method=\"get\">\n\
		<select name=\"hideidle\">\n\
		<option value=\"0\" ##HIDEIDLECLIENTSSELECTED0##>Show idle clients</option>\n\
		<option value=\"1\" ##HIDEIDLECLIENTSSELECTED1##>Hide idle clients</option>\n\
		<option value=\"2\">Show hidden clients</option>\n\
		</select>\n\
		<input type=\"submit\" value=\"Update\">\n\
		</form>\n\
		<TABLE WIDTH=\"100%\" cellspacing=\"0\" class=\"status\">\n\
		<TR>\n\
		<TH>hide</TH>\n\
		<TH>PID</TH>\n\
		<TH>Type</TH>\n\
		<TH>ID</TH>\n\
		<TH>Label</TH>\n\
		<TH>AU</TH>\n\
		<TH>Crypted</TH>\n\
		<TH>Address</TH>\n\
		<TH>Port</TH>\n\
		<TH>Protocol</TH>\n\
		<TH>Login Date</TH>\n\
		<TH>Login Time</TH>\n\
		<TH>Online</TH>\n\
		<TH>CAID:SRVID</TH>\n\
		<TH>Current Channel</TH>\n\
		<TH>LB Value/ Reader</TH>\n\
		<TH>Idle</TH>\n\
		<TH>Status</TH>\n\
		</TR>\n\
		##CLIENTSTATUS##\
		</TABLE><BR>\n\
		<DIV class=\"log\">\n\
		##LOGHISTORY##\
		</DIV><BR>\n\
		##SDEBUG##\
		##TPLFOOTER##"

#define TPLCLIENTSTATUSBIT "\
		<TR class=\"##CLIENTTYPE##\">\n\
		<TD align=\"center\" WIDTH=\"10\"><A HREF =\"status.html?hide=##HIDEIDX##\" TITLE=\"Hide this client\"><IMG SRC=\"##HIDEICON##\" ALT=\"Hide\"></A></TD>\n\
		<TD align=\"center\">##CLIENTPID##</TD>\n\
		<TD align=\"center\">##CLIENTTYPE##</TD>\n\
		<TD align=\"center\">##CLIENTCNR##</TD>\n\
		<TD>##CLIENTUSER##</TD>\n\
		<TD align=\"center\">##CLIENTCAU##</TD>\n\
		<TD align=\"center\">##CLIENTCRYPTED##</TD>\n\
		<TD align=\"center\">##CLIENTIP##</TD>\n\
		<TD align=\"center\">##CLIENTPORT##</TD>\n\
		<TD>##CLIENTPROTO##</TD>\n\
		<TD align=\"center\">##CLIENTLOGINDATE##</TD>\n\
		<TD align=\"center\">##CLIENTLOGINTIME##</TD>\n\
		<TD align=\"center\">##CLIENTLOGINSECS##</TD>\n\
		<TD align=\"center\">##CLIENTCAID##:##CLIENTSRVID##</TD>\n\
		<TD>##CLIENTSRVPROVIDER####CLIENTSRVNAME##</TD>\n\
		<TD align=\"center\">##CLIENTLBVALUE##</TD>\n\
		<TD align=\"center\">##CLIENTIDLESECS##</TD>\n\
		<TD align=\"center\">##CLIENTCON##</TD>\n\
		</TR>\n"

#define TPLUSERCONFIGLIST "\
		##TPLHEADER##\
		##TPLMENU##\n\
		##MESSAGE##\
		<BR>\
		<TABLE CLASS=\"configmenu\">\
		<TR>\
		<TD CLASS=\"configmenu\"><A HREF=\"userconfig.html?part=adduser\">Add User</TD>\
		<TD CLASS=\"configmenu\"><A HREF=\"userconfig.html?action=reinit\">Reinit User DB</TD>\
		</TR>\
		</TABLE><BR>\
		<TABLE cellspacing=\"0\" cellpadding=\"10\">\n\
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
		<TH colspan=\"2\" align=\"center\">Action</TH>\n\
		</TR>\n\
		##USERCONFIGS##\
		##NEWUSERFORM##\
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
		<TD align=\"center\"><A HREF=\"userconfig.html?user=##USERENC##&action=##SWITCH##\" TITLE=\"##SWITCHTITLE##\"><IMG SRC=\"##SWITCHICO##\"BORDER=\"0\" ALT=\"##SWITCHTITLE##\"/></A></TD>\n\
		<TD>##USER##</TD>\n\
		<TD>##STATUS####EXPIRED##</TD>\n\
		<TD align=\"center\">##CLIENTPROTO##</TD>\n\
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
		<TD align=\"center\"><A HREF=\"user_edit.html?user=##USERENC##\" TITLE=\"edit this user\"><IMG SRC=\"##EDIICO##\" BORDER=\"0\" ALT=\"Edit User\"/></A></TD>\n\
		<TD align=\"center\"><A HREF=\"userconfig.html?user=##USERENC##&action=delete\" TITLE=\"delete this user\"><IMG SRC=\"##DELICO##\"BORDER=\"0\" ALT=\"Delete User\"/></A></TD>\n\
		</TR>\n"

#define TPLUSEREDIT "\
##TPLHEADER##\
##TPLMENU##\n\
<DIV CLASS=\"message\">##MESSAGE##</DIV>\
<BR><BR>\n\
  <form action=\"user_edit.html\" method=\"get\">\n\
  <input name=\"user\" type=\"hidden\" value=\"##USERNAME##\">\n\
  <TABLE cellspacing=\"0\">\n\
    <TR><TH>&nbsp;</TH> <TH>Edit User ##USERNAME##</TH></TR>\n\
    <TR><TD>Password:</TD><TD><input name=\"pwd\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##PASSWORD##\"></TD></TR>\n\
    <TR><TD>Disabled:</TD><TD><SELECT NAME=\"disabled\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##DISABLEDCHECKED##>YES</OPTION></SELECT></TD></TR>\n\
    <TR><TD>Exp. Date:</TD><TD><input name=\"expdate\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##EXPDATE##\"></TD></TR>\n\
    <TR><TD>Allowed Timeframe:</TD><TD><input name=\"allowedtimeframe\" type=\"text\" size=\"15\" maxlength=\"11\" value=\"##ALLOWEDTIMEFRAME##\">&nbsp;(hh:mm-hh:mm)</TD></TR>\n\
    <TR><TD>Group:</TD><TD><input name=\"group\" type=\"text\" size=\"20\" maxlength=\"20\" value=\"##GROUPS##\"></TD></TR>\n\
    <TR><TD>Hostname:</TD><TD><input name=\"hostname\" type=\"text\" size=\"60\" maxlength=\"50\" value=\"##DYNDNS##\"></TD></TR>\n\
    <TR><TD>Uniq:</TD><TD><select name=\"uniq\">\n\
        <option value=\"0\" ##UNIQSELECTED0##>0 - none</option>\n\
        <option value=\"1\" ##UNIQSELECTED1##>1 - strict first</option>\n\
        <option value=\"2\" ##UNIQSELECTED2##>2 - per IP</option>\n\
        <option value=\"3\" ##UNIQSELECTED3##>3 - strict last</option>\n\
        <option value=\"4\" ##UNIQSELECTED4##>4 - per IP last</option>\n\
      </SELECT></TD></TR>\n\
    <TR><TD>Sleep:</TD><TD><input name=\"sleep\" type=\"text\" size=\"4\" maxlength=\"4\" value=\"##SLEEP##\"></TD></TR>\n\
    <TR><TD>Monlevel:</TD><TD><select name=\"monlevel\">\n\
        <option value=\"0\" ##MONSELECTED0##>0 - no access to monitor</option>\n\
        <option value=\"1\" ##MONSELECTED1##>1 - only server and own procs</option>\n\
        <option value=\"2\" ##MONSELECTED2##>2 - all procs, but viewing only, default</option>\n\
        <option value=\"3\" ##MONSELECTED3##>3 - all procs, reload of oscam.user possible</option>\n\
        <option value=\"4\" ##MONSELECTED4##>4 - complete access</option>\n\
      </select></TD></TR>\n\
    <TR><TD>AU:</TD><TD><select name=\"au\">\n\
        <option value=\" \" ##AUSELECTED##>none</option>\n\
        <option value=\"1\" ##AUTOAUSELECTED##>auto</option>\n\
        ##RDROPTION##\
      </select></TD></TR>\n\
    <TR><TD>Services:</TD><TD>\n\
        <TABLE cellspacing=\"0\" class=\"invisible\">##SIDS##\
            </TD>\n\
          </TR>\n\
        </TABLE>\n\
    <TR><TD>CAID:</TD><TD><input name=\"caid\" type=\"text\" size=\"60\" maxlength=\"50\" value=\"##CAIDS##\"></TD></TR>\n\
    <TR><TD>Ident:</TD>     <TD><textarea name=\"ident\"      cols=\"58\" rows=\"3\" class=\"bt\">##IDENTS##</textarea></TD></TR>\n\
    <TR><TD>CHID:</TD>     <TD><textarea name=\"chid\"      cols=\"58\" rows=\"3\" class=\"bt\">##CHIDS##</textarea></TD></TR>\n\
    <TR><TD>Betatunnel:</TD><TD><textarea name=\"betatunnel\" cols=\"58\" rows=\"3\" class=\"bt\">##BETATUNNELS##</textarea></TD></TR>\n\
    <TR><TD>Suppresscmd08:</TD><TD><SELECT NAME=\"suppresscmd08\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##SUPPRESSCMD08##>ON</OPTION></SELECT></TD></TR>\n\
    <TR><TD>Sleepsend:</TD><TD><input name=\"sleepsend\" type=\"text\" size=\"3\" maxlength=\"3\" value=\"##SLEEPSEND##\"> 0 or 255</TD></TR>\n\
    ##TPLUSEREDITANTICASC##\
    <TR class=\"usrcfg_cccam\"><TD>CCC Maxhops:</TD><TD><input name=\"cccmaxhops\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##CCCMAXHOPS##\"></TD></TR>\n\
    <TR class=\"usrcfg_cccam\"><TD>CCC Reshare:</TD><TD><input name=\"cccreshare\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##CCCRESHARE##\"></TD></TR>\n\
    <TR><TD>Keepalive:</TD><TD><SELECT NAME=\"keepalive\"><OPTION VALUE=\"0\">OFF</OPTION><OPTION VALUE=\"1\" ##KEEPALIVE##>ON</OPTION></SELECT></TD></TR>\n\
    <TR>\
      <TD align=\"center\"><input type=\"submit\" name=\"action\" value=\"Save\" title=\"Save settings and reload users\" ##BTNDISABLED##></TD>\n\
      <TD align=\"center\"><input name=\"newuser\" type=\"text\" size=\"20\" maxlength=\"20\" title=\"Enter new username if you want to clone this user\">&nbsp;&nbsp;&nbsp;<input type=\"submit\" name=\"action\" value=\"Save As\" title=\"Save as new user and reload users\" ##BTNDISABLED##></TD>\n\
    </TR>\n\
  </TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLUSEREDITRDRSELECTED "\t<option value=\"##READERNAME##\" ##SELECTED##>##READERNAME##</option>"

#define TPLUSEREDITSIDOKBIT "\
          <TR>\n\
            <TD><INPUT NAME=\"services\" TYPE=\"CHECKBOX\" VALUE=\"##SIDLABEL##\" ##CHECKED##> ##SIDLABEL##</TD>\n"

#define TPLUSEREDITSIDNOBIT "\
            <TD><INPUT NAME=\"services\" TYPE=\"CHECKBOX\" VALUE=\"!##SIDLABEL##\" ##CHECKED##> !##SIDLABEL##</TD>\n\
          </TR>\n"

#ifdef CS_ANTICASC
# define TPLUSEREDITANTICASC "\
    <TR class=\"usrcfg_anticasc\"><TD>Anticascading numusers:</TD><TD><input name=\"numusers\" type=\"text\" size=\"3\" maxlength=\"3\" value=\"##AC_USERS##\"></TD></TR>\n\
    <TR class=\"usrcfg_anticasc\"><TD>Anticascading penalty:</TD><TD><input name=\"penalty\" type=\"text\" size=\"3\" maxlength=\"3\" value=\"##AC_PENALTY##\"></TD></TR>\n"
#endif

#define TPLSIDTAB "\
  ##TPLHEADER##\
  ##TPLMENU##\n\
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
##TPLMENU##\n\
<BR><BR>\n\
  <TABLE CLASS=\"configmenu\"><TR><TD CLASS=\"configmenu\"><A HREF=\"scanusb.html\">Scan USB</A></TD></TR></TABLE><BR>\
  <TABLE cellspacing=\"0\" cellpadding=\"10\">\n\
    <TR>\n\
	  <TH>Delete</TH>\n\
      <TH>Reader</TH>\n\
      <TH>Protocol</TH>\n\
      <TH>EMM error<br><span title=\"unknown EMM\"> UK </span>/<span title=\"global EMM\"> G </span>/<span title=\"shared EMM\"> S </span>/<span title=\"unique EMM\"> UQ </span></TH>\n\
      <TH>EMM written<br><span title=\"unknown EMM\"> UK </span>/<span title=\"global EMM\"> G </span>/<span title=\"shared EMM\"> S </span>/<span title=\"unique EMM\"> UQ </span></TH>\n\
      <TH>EMM skipped<br><span title=\"unknown EMM\"> UK </span>/<span title=\"global EMM\"> G </span>/<span title=\"shared EMM\"> S </span>/<span title=\"unique EMM\"> UQ </span></TH>\n\
      <TH>EMM blocked<br><span title=\"unknown EMM\"> UK </span>/<span title=\"global EMM\"> G </span>/<span title=\"shared EMM\"> S </span>/<span title=\"unique EMM\"> UQ </span></TH>\n\
      <TH COLSPAN=\"4\">Action</TH>\n\
    </TR>\n\
    ##READERLIST##\
    <TR>\
		<form action=\"readerconfig.html\" method=\"get\">\n\
		<TD>&nbsp;</TD>\
		<TD COLSPAN=\"2\" align=\"center\">New Reader</TD>\
		<TD COLSPAN=\"2\" align=\"center\">Label:&nbsp;&nbsp;<input type=\"text\" name=\"label\" value=\"##NEXTREADER##\"></TD>\
		<TD COLSPAN=\"2\" align=\"center\">Protocol:&nbsp;&nbsp;<select name=\"protocol\">\
			<option>mouse</option>\
			<option>mp35</option>\
			<option>smartreader</option>\
			<option>internal</option>\
			<option>serial</option>\
			<option>camd35</option>\
			<option>cs378x</option>\
			<option>radegast</option>\
			<option>newcamd525</option>\
			<option>newcamd524</option>\
			<option>cccam</option>\
			<option>gbox</option>\
			<option>pcsc</option>\
			<option>constcw</option>\
		</select></TD>\
		<TD COLSPAN=\"4\" align=\"center\"><input type=\"submit\" name=\"action\" value=\"Add\" ##BTNDISABLED##></TD></TR>\
		</form>\
  </TABLE>\n\
##TPLFOOTER##"

#define TPLREADERSBIT "\
    <TR>\n\
	<TD align=\"center\"><A HREF=\"readers.html?reader=##READERIDX##&action=delete\" TITLE=\"Delete this Reader\"><IMG SRC=\"##DELICO##\" BORDER=\"0\" ALT=\"Delete Reader\"/></A></TD>\n\
      <TD>##READERNAME##</TD>\n\
      <TD>##CTYP##</TD>\n\
      <TD align=\"center\">##EMMERRORUK## / ##EMMERRORG## / ##EMMERRORS## / ##EMMERRORUQ##</TD>\n\
      <TD align=\"center\">##EMMWRITTENUK## / ##EMMWRITTENG## / ##EMMWRITTENS## / ##EMMWRITTENUQ##</TD>\n\
      <TD align=\"center\">##EMMSKIPPEDUK## / ##EMMSKIPPEDG## / ##EMMSKIPPEDS## / ##EMMSKIPPEDUQ##</TD>\n\
      <TD align=\"center\">##EMMBLOCKEDUK## / ##EMMBLOCKEDG## / ##EMMBLOCKEDS## / ##EMMBLOCKEDUQ##</TD>\n\
      <TD align=\"center\"><A HREF=\"readerconfig.html?reader=##READERNAMEENC##\" TITLE=\"Edit this Reader\"><IMG SRC=\"##EDIICO##\" BORDER=\"0\" ALT=\"Edit Reader\"/></A></TD>\
      <TD align=\"center\">##ENTITLEMENT##</TD>\n\
	  <TD align=\"center\">##READERREFRESH##</TD>\n\
	  <TD align=\"center\"><A HREF=\"readerstats.html?reader=##READERID##&hide=4\" TITLE=\"Show loadbalancer statistics\"><IMG SRC=\"##STATICO##\" BORDER=\"0\" ALT=\"Loadbalancer statistics\"/></A></TD>\n\
      </TR>\n"

#define TPLREADERENTITLEBIT "<A HREF=\"entitlements.html?reader=##READERNAMEENC##\" TITLE=\"Show Entitlement\"><IMG SRC=\"##ENTICO##\" BORDER=\"0\" ALT=\"Show Entitlement\"/></A>\n"

#define TPLREADERREFRESHBIT "<A HREF=\"readers.html?action=reread&ridx=##RIDX##\" TITLE=\"Refresh Entitlement\"><IMG SRC=\"##REFRICO##\" BORDER=\"0\" ALT=\"Reset and reload Entitlement\"/></A>"

#define TPLREADERSTATS "\
##TPLHEADER##\
##TPLMENU##\n\
	<BR><BR>\n\
	<TABLE border=0 class=\"configmenu\">\n\
		<TR>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"readerstats.html?reader=##READERID##&hide=-1\">show all</A></TD>\n\
			<TD CLASS=\"configmenu\"><A HREF=\"readerstats.html?reader=##READERID##&hide=4\">hide 'not found'</A></TD>\n\
		</TR>\n\
	</TABLE>\
	<BR><BR>\n\
	<TABLE cellspacing=\"0\" cellpadding=\"10\">\n\
	<TR><TH colspan=\"6\"> Loadbalance statistics for reader ##READERNAME##</TH></TR>\n\
	<TR><TH>Channel</TH><TH>Channelname</TH><TH>Result</TH><TH>Time</TH><TH>Count</TH><TH>Last checked/ found</TH></TR>\n\
    ##READERSTATSROW##\n\
	</TABLE>\n\
##TPLFOOTER##"

#define TPLREADERSTATSBIT "\
	<TR><TD>##CHANNEL##</TD>\
	<TD>##CHANNELNAME##</TD>\
	<TD align=\"center\">##RC##</TD>\
	<TD align=\"center\">##TIME##</TD>\
	<TD align=\"center\">##COUNT##</TD>\
	<TD align=\"center\">##LAST##</TD></TR>\n"

#define TPLSCANUSB "\
##TPLHEADER##\
##TPLMENU##\n\
<BR><BR>\n\
<TABLE cellspacing=\"0\" cellpadding=\"10\">\n\
    <TR><TH>USB Devices</TH></TR>\n\
    ##USBBIT##\n\
</TABLE>\n\
##TPLFOOTER##"

#define TPLSCANUSBBIT "<TR ##USBENTRYCLASS##><TD>##USBENTRY##</TD></TR>\n"

#define TPLENTITLEMENTS "\
##TPLHEADER##\
##TPLMENU##\n\
<BR><BR>Entitlements for ##READERNAME##<BR><BR>\n\n\
<DIV class=\"log\">\n\
  ##LOGSUMMARY##\
  ##LOGHISTORY##\
</DIV>\n\
##TPLFOOTER##"

#define TPLREADERCONFIG "\
##TPLHEADER##\
##TPLMENU##\n\
<BR><BR>\n\
##MESSAGE##\
  <form action=\"readerconfig.html?action=execute\" method=\"get\">\n\
  <input name=\"reader\" type=\"hidden\" value=\"##READERNAME##\">\n\
  <input name=\"protocol\" type=\"hidden\" value=\"##PROTOCOL##\">\n\
  <TABLE cellspacing=\"0\">\n\
    <TR><TH COLSPAN=\"2\">Edit Reader ##READERNAME##</TH></TR>\n\
    <TR><TH>&nbsp;</TH><TH>Reader general settings</TH></TR>\n\
    <TR><TD>Enable:</TD><TD><input name=\"enable\" type=\"hidden\" value=\"0\"><input name=\"enable\" type=\"checkbox\" value=\"1\" ##ENABLED##></TD></TR>\n\
    <TR><TD>AU disabled:</TD><TD><input name=\"audisabled\" type=\"hidden\" value=\"0\"><input name=\"audisabled\" type=\"checkbox\" value=\"1\" ##AUDISABLED##></TD></TR>\n\
    <TR><TD>AU Provid:</TD><TD><input name=\"auprovid\" type=\"text\" size=\"10\" maxlength=\"6\" value=\"##AUPROVID##\"></TD></TR>\n\
	<TR><TD>Fallback:</TD><TD><input name=\"fallback\" type=\"hidden\" value=\"0\"><input name=\"fallback\" type=\"checkbox\" value=\"1\" ##FALLBACKCHECKED##></TD></TR>\n\
    <TR><TD>Group:</TD><TD><input name=\"group\" type=\"text\" size=\"10\" maxlength=\"10\" value=\"##GRP##\"></TD></TR>\n\
    <TR><TD>Device:</TD><TD><input name=\"device\" type=\"text\" size=\"60\" maxlength=\"150\" value=\"##DEVICE##\"></TD></TR>\n\
    <TR><TD>Caid:</TD><TD><input name=\"caid\" type=\"text\" size=\"60\" maxlength=\"100\" value=\"##CAIDS##\"></TD></TR>\n\
    <TR><TD>Ident:</TD>     <TD><textarea name=\"ident\"      cols=\"58\" rows=\"3\" class=\"bt\">##IDENTS##</textarea></TD></TR>\n\
    <TR><TD>CHID:</TD>     <TD><textarea name=\"chid\"      cols=\"58\" rows=\"3\" class=\"bt\">##CHIDS##</textarea></TD></TR>\n\
    <TR><TD>Emmcache:</TD><TD><input name=\"emmcache\" type=\"text\" size=\"10\" maxlength=\"10\" value=\"##EMMCACHE##\"></TD></TR>\n\
    <TR><TD>Blockemm:</TD><TD>\n<TABLE cellspacing=\"0\" class=\"invisible\">\
		<TR><TD align=\"center\">unknown</TD><TD align=\"center\">unique</TD><TD align=\"center\">shared</TD><TD align=\"center\">global</TD></TR>\
		<TR><TD align=\"center\"><input name=\"blockemm-unknown\" type=\"hidden\" value=\"0\"><input name=\"blockemm-unknown\" type=\"checkbox\" value=\"1\" ##BLOCKEMMUNKNOWNCHK##></TD>\n\
			<TD align=\"center\"><input name=\"blockemm-u\" type=\"hidden\" value=\"0\"><input name=\"blockemm-u\" type=\"checkbox\" value=\"1\" ##BLOCKEMMUNIQCHK##></TD>\n\
			<TD align=\"center\"><input name=\"blockemm-s\" type=\"hidden\" value=\"0\"><input name=\"blockemm-s\" type=\"checkbox\" value=\"1\" ##BLOCKEMMSHAREDCHK##></TD>\n\
			<TD align=\"center\"><input name=\"blockemm-g\" type=\"hidden\" value=\"0\"><input name=\"blockemm-g\" type=\"checkbox\" value=\"1\" ##BLOCKEMMGLOBALCHK##></TD></TR>\n\
    </TD>\n</TR>\n</TABLE>\n\
    <TR><TD>Ecmcache:<input name=\"ecmcache\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"ecmcache\" type=\"checkbox\" value=\"1\" ##ECMCACHECHECKED##></TD></TR>\n\
    <TR><TD>Loadbalance weight:</TD><TD><input name=\"lb_weight\" type=\"text\" size=\"5\" maxlength=\"4\" value=\"##LBWEIGHT##\"></TD></TR>\n\
	<TR><TD>Services:</TD><TD>\n<TABLE cellspacing=\"0\" class=\"invisible\">##SIDS##</TD>\n</TR>\n</TABLE>\n\
    <TR><TH>&nbsp;</TH><TH>Reader specific settings for protocol ##PROTOCOL##</TH></TR>\n\
    ##READERDEPENDINGCONFIG##\
    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" name=\"action\" value=\"Save\" ##BTNDISABLED##>\n</TD></TR>\n\
  </TABLE>\n\
	<BR><BR>\n\
##TPLFOOTER##"
#define TPLSAVETEMPLATES "##TPLHEADER##\
##TPLMENU##\n\
<br><b>Saved ##CNT## templates to ##PATH##</b><br>\n\
##TPLFOOTER##"
#define TPLREADERCONFIGSIDOKBIT "\
          <TR>\n\
            <TD><INPUT NAME=\"services\" TYPE=\"CHECKBOX\" VALUE=\"##SIDLABEL##\" ##CHECKED##> ##SIDLABEL##</TD>\n"

#define TPLREADERCONFIGSIDNOBIT "\
            <TD><INPUT NAME=\"services\" TYPE=\"CHECKBOX\" VALUE=\"!##SIDLABEL##\" ##CHECKED##> !##SIDLABEL##</TD>\n\
          </TR>\n"

#define TPLREADERCONFIGSTDHWREADERBIT "\
    <TR><TD>Smargopatch:<input name=\"smargopatch\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"smargopatch\" type=\"checkbox\" value=\"1\" ##SMARGOPATCHCHECKED##></TD></TR>\n\
    <TR><TD>Pincode:</TD><TD><input name=\"pincode\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PINCODE##\"></TD></TR>\n\
    <TR><TD>Disableserverfilter:</TD><TD><input name=\"disableserverfilter\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##DISABLESERVERFILTER##\"></TD></TR>\n\
    <TR><TD>Force Irdeto:<input name=\"force_irdeto\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"force_irdeto\" type=\"checkbox\" value=\"1\" ##FORCEIRDETOCHECKED##></TD></TR>\n\
    <TR><TD>Boxid:</TD><TD><input name=\"boxid\" type=\"text\" size=\"15\" maxlength=\"8\" value=\"##BOXID##\"></TD></TR>\n\
    <TR><TD>AES Key:</TD><TD><input name=\"aeskey\" type=\"text\" size=\"35\" maxlength=\"32\" value=\"##AESKEY##\"></TD></TR>\n\
    <TR><TD>RSA key:</TD><TD><textarea name=\"rsakey\" cols=\"98\" rows=\"4\" class=\"bt\" maxlength=\"128\">##RSAKEY##</textarea></TD></TR>\n\
    <TR><TD>Tiger RSA key:</TD><TD><textarea name=\"tiger_rsakey\" cols=\"98\" rows=\"6\" class=\"bt\" maxlength=\"240\">##TIGERRSAKEY##</textarea></TD></TR>\n\
    <TR><TD>Boxkey:</TD><TD><input name=\"boxkey\" type=\"text\" size=\"20\" maxlength=\"16\" value=\"##BOXKEY##\"></TD></TR>\n\
    <TR><TD>ATR:</TD><TD><input name=\"atr\" type=\"text\" size=\"100\" maxlength=\"54\" value=\"##ATR##\"></TD></TR>\n\
    <TR><TD>Detect:</TD><TD><input name=\"detect\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##DETECT##\"></TD></TR>\n\
    <TR><TD>Mhz:</TD><TD><input name=\"mhz\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##MHZ##\"></TD></TR>\n\
    <TR><TD>Cardmhz:</TD><TD><input name=\"cardmhz\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##CARDMHZ##\"></TD></TR>\n\
    <TR><TD>Deprecated:<input name=\"deprecated\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"deprecated\" type=\"checkbox\" value=\"1\" ##DEPRECATEDCHCHECKED##></TD></TR>\n\
    <TR><TD>Readnano:</TD><TD><input name=\"readnano\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##EMMFILE##\"></TD></TR>\n\
    <TR><TD>Blocknano:</TD><TD><input name=\"blocknano\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##BLOCKNANO##\"></TD></TR>\n\
    <TR><TD>Savenano:</TD><TD><input name=\"savenano\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##SAVENANO##\"></TD></TR>\n\
    <TR><TD>Force NDS Version:</TD><TD><SELECT name=\"ndsversion\">\
                        <OPTION  value=\"0\" ##NDSVERSION0##>0 - AUTO</OPTION>\
                        <OPTION  value=\"1\" ##NDSVERSION1##>1 - NDS1 Forced</OPTION>\
                        <OPTION  value=\"12\" ##NDSVERSION21##>12 - NDS1+ Forced</OPTION>\
                        <OPTION  value=\"2\" ##NDSVERSION2##>2 - NDS2 Forced</OPTION>\
                </SELECT></TD></TR>\n"
#define TPLREADERCONFIGCAMD35BIT "\
    <TR><TD>Account:</TD><TD><input name=\"account\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
    <TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
    <TR><TD>Reconnect timeout:</TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
    <TR><TD>Disable server filter:</TD><TD><input name=\"disableserverfilter\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##DISABLESERVERFILTER##\"></TD></TR>\n"
#define TPLREADERCONFIGCS378XBIT "\
    <TR><TD>Account:</TD><TD><input name=\"account\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
    <TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
    <TR><TD>Key:</TD><TD><input name=\"key\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##NCD_KEY##\"></TD></TR>\n\
    <TR><TD>Reconnect timeout:</TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
    <TR><TD>Disable server filter:</TD><TD><input name=\"disableserverfilter\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##DISABLESERVERFILTER##\"></TD></TR>\n"
#define TPLREADERCONFIGRADEGASTBIT "\
	<TR><TD>Account:</TD><TD><input name=\"account\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
	<TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
    <TR><TD>Inactivity timeout:</TD><TD><input name=\"inactivitytimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##INACTIVITYTIMEOUT##\"></TD></TR>\n\
    <TR><TD>Reconnect timeout:</TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
    <TR><TD>Disable server filter:</TD><TD><input name=\"disableserverfilter\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##DISABLESERVERFILTER##\"></TD></TR>\n"
#define TPLREADERCONFIGNCD525BIT "\
	<TR><TD>Account:</TD><TD><input name=\"account\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
	<TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
    <TR><TD>Key:</TD><TD><input name=\"key\" type=\"text\" size=\"40\" maxlength=\"28\" value=\"##NCD_KEY##\"></TD></TR>\n\
    <TR><TD>Inactivity timeout:</TD><TD><input name=\"inactivitytimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##INACTIVITYTIMEOUT##\"></TD></TR>\n\
    <TR><TD>Reconnect timeout:</TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
    <TR><TD>Disable server filter:</TD><TD><input name=\"disableserverfilter\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##DISABLESERVERFILTER##\"></TD></TR>\n"
#define TPLREADERCONFIGNCD524BIT "\
	<TR><TD>Account:</TD><TD><input name=\"account\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
	<TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
    <TR><TD>Key:</TD><TD><input name=\"key\" type=\"text\" size=\"40\" maxlength=\"28\" value=\"##NCD_KEY##\"></TD></TR>\n\
    <TR><TD>Inactivity timeout:</TD><TD><input name=\"inactivitytimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##INACTIVITYTIMEOUT##\"></TD></TR>\n\
    <TR><TD>Reconnect timeout:</TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
    <TR><TD>Disable server filter:</TD><TD><input name=\"disableserverfilter\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##DISABLESERVERFILTER##\"></TD></TR>\n"
#define TPLREADERCONFIGCCCAMBIT "\
	<TR><TD>Account:</TD><TD><input name=\"account\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
	<TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##PASSWORD##\"></TD></TR>\n\
    <TR><TD>Version:</TD><TD><SELECT name=\"cccversion\">\
			<OPTION ##CCCVERSIONSELECTED0##>2.0.11</OPTION>\
			<OPTION ##CCCVERSIONSELECTED1##>2.1.1</OPTION>\
			<OPTION ##CCCVERSIONSELECTED2##>2.1.2</OPTION>\
			<OPTION ##CCCVERSIONSELECTED3##>2.1.3</OPTION>\
			<OPTION ##CCCVERSIONSELECTED4##>2.1.4</OPTION>\
		</SELECT></TD></TR>\n\
    <TR><TD>Maxhop:</TD><TD><input name=\"cccmaxhop\" type=\"text\" size=\"3\" maxlength=\"2\" value=\"##CCCMAXHOP##\"></TD></TR>\n\
    <TR><TD>Want Emu:<input name=\"cccwantemu\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"cccwantemu\" type=\"checkbox\" value=\"1\" ##CCCWANTEMUCHECKED##></TD></TR>\n\
    <TR><TD>Disable retry ECM: <input name=\"cccdisableretryecm\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"cccdisableretryecm\" type=\"checkbox\" value=\"1\" ##CCCDISABLERETRYECMCHECKED##></TD></TR>\n\
    <TR><TD>Disable auto blocking of undecodable channels: <input name=\"cccdisableautoblock\" type=\"hidden\" value=\"0\"></TD><TD><input name=\"cccdisableautoblock\" type=\"checkbox\" value=\"1\" ##CCCDISABLEAUTOBLOCKCHECKED##></TD></TR>\n\
    <TR><TD>Reconnect-timeout:</TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
    <TR><TD>Disable server filter:</TD><TD><input name=\"disableserverfilter\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##DISABLESERVERFILTER##\"></TD></TR>\n\
    <TR><TD>Keep alive:</TD><TD><SELECT NAME=\"ccckeepalive\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##KEEPALIVECHECKED##>YES</OPTION></SELECT></TD></TR>\n"
#ifdef CS_WITH_GBOX
#define TPLREADERCONFIGGBOXBIT "\
	<TR><TD>Account:</TD><TD><input name=\"account\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##ACCOUNT##\"></TD></TR>\n\
    <TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"10\" maxlength=\"8\" value=\"##PASSWORD##\"></TD></TR>\n\
    <TR><TD>Inactivity timeout:</TD><TD><input name=\"inactivitytimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##INACTIVITYTIMEOUT##\"></TD></TR>\n\
    <TR><TD>Reconnect timeout:</TD><TD><input name=\"reconnecttimeout\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##RECEIVETIMEOUT##\"></TD></TR>\n\
    <TR><TD>Disable server filter:</TD><TD><input name=\"disableserverfilter\" type=\"text\" size=\"30\" maxlength=\"50\" value=\"##DISABLESERVERFILTER##\"></TD></TR>\n"
#endif

#define TPLCONFIGGBOX "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
<DIV CLASS=\"message\">##MESSAGE##</DIV>\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"gbox\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Gbox Config </TH></TR>\n\
		<TR><TD>Password:</TD><TD><input name=\"password\" type=\"text\" size=\"10\" maxlength=\"8\" value=\"##PASSWORD##\"></TD></TR>\n\
		<TR><TD>Maxdist:</TD><TD><input name=\"maxdist\" type=\"text\" size=\"5\" maxlength=\"2\" value=\"##MAXDIST##\"></TD></TR>\n\
		<TR><TD>Ignorelist:</TD><TD><input name=\"ignorelist\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##IGNORELIST##\"></TD></TR>\n\
		<TR><TD>Onlineinfos:</TD><TD><input name=\"onlineinfos\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##ONLINEINFOS##\"></TD></TR>\n\
		<TR><TD>Cardinfos:</TD><TD><input name=\"cardinfos\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##CARDINFOS##\"></TD></TR>\n\
		<TR><TD>Locals:</TD><TD><input name=\"locals\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##LOCALS##\"></TD></TR>\n\
    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
##TPLFOOTER##"

#ifdef CS_ANTICASC
#define TPLCONFIGANTICASC "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"anticasc\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<input name=\"enabled\" type=\"hidden\" value=\"0\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Anticascading Config</TH></TR>\n\
		<TR><TD>Enabled:</TD><TD><input name=\"enabled\" type=\"checkbox\" value=\"1\" ##CHECKED##>\n\
		<TR><TD>Numusers:</TD><TD><input name=\"numusers\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##NUMUSERS##\"></TD></TR>\n\
		<TR><TD>Sampletime:</TD><TD><input name=\"sampletime\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SAMPLETIME##\"></TD></TR>\n\
		<TR><TD>Samples:</TD><TD><input name=\"samples\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SAMPLES##\"></TD></TR>\n\
		<TR><TD>Penalty:</TD><TD><input name=\"penalty\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##PENALTY##\"></TD></TR>\n\
		<TR><TD>AClogfile:</TD><TD><input name=\"aclogfile\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##ACLOGFILE##\"></TD></TR>\n\
		<TR><TD>Fakedelay:</TD><TD><input name=\"fakedelay\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##FAKEDELAY##\"></TD></TR>\n\
		<TR><TD>Denysamples:</TD><TD><input name=\"denysamples\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##DENYSAMPLES##\"></TD></TR>\n\
    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"
#endif

#define TPLCONFIGCCCAM "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"cccam\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Cccam Config</TH></TR>\n\
		<TR><TD>Port:</TD><TD><input name=\"port\" type=\"text\" size=\"6\" maxlength=\"6\" value=\"##PORT##\"></TD></TR>\n\
		<TR><TD>Reshare:</TD><TD><input name=\"reshare\" type=\"text\" size=\"2\" maxlength=\"1\" value=\"##RESHARE##\"></TD></TR>\n\
		<TR><TD>Version:</TD><TD><SELECT name=\"version\">\
			<OPTION ##VERSIONSELECTED0##>2.0.11</OPTION>\
			<OPTION ##VERSIONSELECTED1##>2.1.1</OPTION>\
			<OPTION ##VERSIONSELECTED2##>2.1.2</OPTION>\
			<OPTION ##VERSIONSELECTED3##>2.1.3</OPTION>\
			<OPTION ##VERSIONSELECTED4##>2.1.4</OPTION>\
		</SELECT></TD></TR>\n\
		<TR><TD>Update Interval:</TD><TD><input name=\"updateinterval\" type=\"text\" size=\"5\" maxlength=\"4\" value=\"##UPDATEINTERVAL##\"></TD></TR>\n\
		<TR><TD>Minimize cards:</TD><TD><SELECT name=\"minimizecards\">\
			<OPTION value=\"0\" ##MINIMIZECARDSELECTED0##>0 - legacy (default)</OPTION>\
			<OPTION value=\"1\" ##MINIMIZECARDSELECTED1##>1 - smallest hop</OPTION>\
			<OPTION value=\"2\" ##MINIMIZECARDSELECTED2##>2 - via caid</OPTION>\
		</SELECT></TD></TR>\n\
		<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLCONFIGMONITOR "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"monitor\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<input name=\"httphideidleclients\" type=\"hidden\" value=\"0\">\n\
	<input name=\"appendchaninfo\" type=\"hidden\" value=\"0\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Monitor Config</TH></TR>\n\
		<TR><TD>Port:</TD><TD><input name=\"port\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##MONPORT##\"></TD></TR>\n\
		<TR><TD>Serverip:</TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
		<TR><TD>No crypt:</TD><TD><input name=\"nocrypt\" type=\"text\" size=\"100\" maxlength=\"200\" value=\"##NOCRYPT##\"></TD></TR>\n\
		<TR><TD>Au low:</TD><TD><input name=\"aulow\" type=\"text\" size=\"5\" maxlength=\"1\" value=\"##AULOW##\"> min</TD></TR>\n\
		<TR>\n\
			<TD>Monlevel:</TD>\n\
	    <TD><select name=\"monlevel\">\n\
				<option value=\"0\" ##MONSELECTED0##>0 - no access to monitor</option>\n\
				<option value=\"1\" ##MONSELECTED1##>1 - only server and own procs</option>\n\
				<option value=\"2\" ##MONSELECTED2##>2 - all procs, but viewing only, default</option>\n\
				<option value=\"3\" ##MONSELECTED3##>3 - all procs, reload of oscam.user possible</option>\n\
				<option value=\"4\" ##MONSELECTED4##>4 - complete access</option>\n\
			</select></TD>\n\
		</TR>\n\
		<TR><TD>Hide client to:</TD><TD><input name=\"hideclient_to\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##HIDECLIENTTO##\"> s</TD></TR>\n\
		<TR><TD>Append channel info:</TD><TD><input name=\"appendchaninfo\" type=\"checkbox\" value=\"1\" ##APPENDCHANINFO##></TD></TR>\n\
		<TR><TH>&nbsp;</TH><TH>Webinterface Config</TH></TR>\n\
		<TR><TD>Http port:</TD><TD><input name=\"httpport\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##HTTPPORT##\"></TD></TR>\n\
		<TR><TD>Http user:</TD><TD><input name=\"httpuser\" type=\"text\" size=\"20\" maxlength=\"20\" value=\"##HTTPUSER##\"></TD></TR>\n\
		<TR><TD>Http pwd:</TD><TD><input name=\"httppwd\" type=\"text\" size=\"20\" maxlength=\"20\" value=\"##HTTPPASSWORD##\"></TD></TR>\n\
		<TR><TD>Http css:</TD><TD><SELECT name=\"httpcss\">##CSSOPTIONS##</select></TD></TR>\n\
		<TR><TD>Http refresh:</TD><TD><input name=\"httprefresh\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##HTTPREFRESH##\"> s</TD></TR>\n\
		<TR><TD>Http tpl:</TD><TD><input name=\"httptpl\" type=\"text\" size=\"50\" maxlength=\"128\" value=\"##HTTPTPL##\"></TD></TR>\n\
		<TR><TD>Http script:</TD><TD><input name=\"httpscript\" type=\"text\" size=\"50\" maxlength=\"128\" value=\"##HTTPSCRIPT##\"></TD></TR>\n\
		<TR><TD>Http Hide Idle Clients:</TD><TD><input name=\"httphideidleclients\" type=\"checkbox\" value=\"1\" ##CHECKED##>\n\
		<TR><TD>Http allowed:</TD><TD><input name=\"httpallowed\" type=\"text\" size=\"100\" maxlength=\"200\" value=\"##HTTPALLOW##\"></TD></TR>\n\
		<TR><TD>Http dyndns:</TD><TD><input name=\"httpdyndns\" type=\"text\" size=\"100\" maxlength=\"200\" value=\"##HTTPDYNDNS##\"></TD></TR>\n\
    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLCONFIGRADEGAST "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"radegast\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Radegast Config</TH></TR>\n\
		<TR><TD>Port:</TD><TD><input name=\"port\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##PORT##\"></TD></TR>\n\
		<TR><TD>Serverip:</TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
		<TR><TD>Allowed:</TD><TD><input name=\"allowed\" type=\"text\" size=\"100\" maxlength=\"200\" value=\"##ALLOWED##\"></TD></TR>\n\
		<TR><TD>User:</TD><TD><input name=\"user\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##USER##\"></TD></TR>\n\
    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLCONFIGNEWCAMD "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"newcamd\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<input name=\"keepalive\" type=\"hidden\" value=\"0\">\n\
	<input name=\"mgclient\" type=\"hidden\" value=\"0\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Newcamd Config</TH></TR>\n\
		<TR><TD>Port:</TD>     <TD><textarea name=\"port\"      cols=\"58\" rows=\"3\" class=\"bt\">##PORT##</textarea></TD></TR>\n\
		<TR><TD>Serverip:</TD><TD><input name=\"serverip\" type=\"text\" size=\"60\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
		<TR><TD>Key:</TD><TD><input name=\"key\" type=\"text\" size=\"60\" maxlength=\"28\" value=\"##KEY##\"></TD></TR>\n\
		<TR><TD>Allowed:</TD>     <TD><textarea name=\"allowed\"      cols=\"58\" rows=\"3\" class=\"bt\">##ALLOWED##</textarea></TD></TR>\n\
		<TR><TD>Keepalive:</TD><TD><input name=\"keepalive\" type=\"checkbox\" value=\"1\" ##KEEPALIVE##></TD></TR>\n\
		<TR><TD>Mgclient:</TD><TD><input name=\"mgclient\" type=\"checkbox\" value=\"1\" ##MGCLIENTCHK##></TD></TR>\n\
		<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLCONFIGGLOBAL "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"global\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<input name=\"disableuserfile\" type=\"hidden\" value=\"0\">\n\
	<input name=\"disablelog\" type=\"hidden\" value=\"0\">\n\
	<input name=\"clientdyndns\" type=\"hidden\" value=\"0\">\n\
	<input name=\"unlockparental\" type=\"hidden\" value=\"0\">\n\
	<input name=\"waitforcards\" type=\"hidden\" value=\"0\">\n\
	<input name=\"preferlocalcards\" type=\"hidden\" value=\"0\">\n\
	<input name=\"saveinithistory\" type=\"hidden\" value=\"0\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Global Config</TH></TR>\n\
		<TR><TD>Serverip:</TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
		<TR><TD>PID File:</TD><TD><input name=\"pidfile\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##PIDFILE##\"></TD></TR>\n\
		<TR><TD>Disable userfile:</TD><TD><input name=\"disableuserfile\" type=\"checkbox\" value=\"1\" ##CHKDISABLEUSERFILE##></TD></TR>\n\
		<TR><TD>Usr file:</TD><TD><input name=\"usrfile\" type=\"text\" size=\"30\" maxlength=\"128\" value=\"##USERFILE##\"></TD></TR>\n\
		<TR><TD>Disable log:</TD><TD><input name=\"disablelog\" type=\"checkbox\" value=\"1\" ##CHKDISABLELOG##></TD></TR>\n\
		<TR><TD>Log file:</TD><TD><input name=\"logfile\" type=\"text\" size=\"30\" maxlength=\"128\" value=\"##LOGFILE##\"></TD></TR>\n\
		<TR><TD>Usr file flag:</TD><TD><input name=\"usrfileflag\" type=\"text\" size=\"5\" maxlength=\"1\" value=\"##USERFILEFLAG##\"></TD></TR>\n\
		<TR><TD>CW log dir:</TD><TD><input name=\"cwlogdir\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##CWLOGDIR##\"></TD></TR>\n\
		<TR><TD>Client timeout:</TD><TD><input name=\"clienttimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##CLIENTTIMEOUT##\"> ms</TD></TR>\n\
		<TR><TD>Fallback timeout:</TD><TD><input name=\"fallbacktimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##FALLBACKTIMEOUT##\"> ms</TD></TR>\n\
		<TR><TD>Cache delay:</TD><TD><input name=\"cachedelay\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##CACHEDELAY##\"> ms</TD></TR>\n\
		<TR><TD>Client max idle:</TD><TD><input name=\"clientmaxidle\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##CLIENTMAXIDLE##\"> s</TD></TR>\n\
		<TR><TD>Bind wait:</TD><TD><input name=\"bindwait\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##BINDWAIT##\"> s</TD></TR>\n\
		<TR><TD>Net prio:</TD><TD><input name=\"netprio\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##NETPRIO##\"></TD></TR>\n\
		<TR><TD>Client dyndns:</TD><TD><input name=\"clientdyndns\" type=\"checkbox\" value=\"1\" ##CHKCLIENTDYNDNS##></TD></TR>\n\
		<TR><TD>Resolve delay:</TD><TD><input name=\"resolvedelay\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##RESOLVEDELAY##\"> s</TD></TR>\n\
		<TR><TD>Sleep:</TD><TD><input name=\"sleep\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SLEEP##\"> min</TD></TR>\n\
		<TR><TD>Unlock parental:</TD><TD><input name=\"unlockparental\" type=\"checkbox\" value=\"1\" ##UNLOCKPARENTAL##></TD></TR>\n\
		<TR><TD>Nice:</TD><TD><input name=\"nice\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##NICE##\"></TD></TR>\n\
		<TR><TD>Serial reader timeout:</TD><TD><input name=\"serialreadertimeout\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##SERIALTIMEOUT##\"> ms</TD></TR>\n\
		<TR><TD>Max log size:</TD><TD><input name=\"maxlogsize\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##MAXLOGSIZE##\"> kB</TD></TR>\n\
		<TR><TD>Wait for cards:</TD><TD><input name=\"waitforcards\" type=\"checkbox\" value=\"1\" ##WAITFORCARDS##></TD></TR>\n\
		<TR><TD>Prefer local cards:</TD><TD><input name=\"preferlocalcards\" type=\"checkbox\" value=\"1\" ##PREFERLOCALCARDS##></TD></TR>\n\
		<TR><TD>Save init history:</TD><TD><input name=\"saveinithistory\" type=\"checkbox\" value=\"1\" ##SAVEINITHISTORY##></TD></TR>\n\
		<TR><TD>Reader restart seconds:</TD><TD><input name=\"readerrestartseconds\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##READERRESTARTSECONDS##\"></TD></TR>\n\
		<TR><TD>Resolver:</TD>\n\
		<TD><select name=\"resolvegethostbyname\">\n\
			<option value=\"0\" ##RESOLVER0##>0 - getadressinfo()</option>\n\
			<option value=\"1\" ##RESOLVER1##>1 - gethostbyname()</option>\n\
		</select></TD></TR>\n\
		##TPLDOUBLECHECKBIT##\
		<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#ifdef CS_WITH_DOUBLECHECK
#define TPLDOUBLECHECKBIT "\
	<TR><TD>ECM Doublecheck:</TD><TD><SELECT NAME=\"double_check\"><OPTION VALUE=\"0\">NO</OPTION><OPTION VALUE=\"1\" ##DCHECKCSELECTED##>YES</OPTION></SELECT></TD></TR>\n"
#endif

#define TPLCONFIGLOADBALANCER "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"loadbalancer\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Loadbalancer Config</TH></TR>\n\
		<TR><TD>Loadbalance Mode:</TD>\n\
			<TD><select name=\"lb_mode\">\n\
					<option value=\"0\" ##LBMODE0##>0 - Loadbalancer disabled (send to all readers)</option>\n\
					<option value=\"1\" ##LBMODE1##>1 - Fastest reader first</option>\n\
					<option value=\"2\" ##LBMODE2##>2 - Oldest reader first</option>\n\
					<option value=\"3\" ##LBMODE3##>3 - Lowest usagelevel</option>\n\
				</select></TD></TR>\n\
		<TR><TD>Loadbalance save every:</TD><TD><input name=\"lb_save\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBSAVE##\"></TD></TR>\n\
		<TR><TD>Number of best readers:</TD><TD><input name=\"lb_nbest_readers\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBNBESTREADERS##\"></TD></TR>\n\
		<TR><TD>Number of fallback readers:</TD><TD><input name=\"lb_nfb_readers\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBNFBREADERS##\"></TD></TR>\n\
		<TR><TD>Min ECM count:</TD><TD><input name=\"lb_min_ecmcount\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBMINECMCOUNT##\"></TD></TR>\n\
		<TR><TD>Max ECM count:</TD><TD><input name=\"lb_max_ecmcount\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBMAXECEMCOUNT##\"></TD></TR>\n\
		<TR><TD>Time to reopen:</TD><TD><input name=\"lb_reopen_seconds\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##LBREOPENSECONDS##\"></TD></TR>\n\
		<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLCONFIGCAMD33 "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"camd33\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<input name=\"passive\" type=\"hidden\" value=\"0\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Camd33 Config</TH></TR>\n\
		<TR><TD>Port:</TD><TD><input name=\"port\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##PORT##\"></TD></TR>\n\
		<TR><TD>Serverip:</TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
		<TR><TD>Key:</TD><TD><input name=\"key\" type=\"text\" size=\"35\" maxlength=\"28\" value=\"##KEY##\"></TD></TR>\n\
		<TR><TD>Passive:</TD><TD><input name=\"passive\" type=\"checkbox\" value=\"1\" ##PASSIVE##></TD></TR>\n\
		<TR><TD>Nocrypt:</TD><TD><input name=\"nocrypt\" type=\"text\" size=\"100\" maxlength=\"200\" value=\"##NOCRYPT##\"></TD></TR>\n\
    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLCONFIGCAMD35 "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"camd35\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<input name=\"suppresscmd08\" type=\"hidden\" value=\"0\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Camd35 Config</TH></TR>\n\
		<TR><TD>Port:</TD><TD><input name=\"port\" type=\"text\" size=\"5\" maxlength=\"5\" value=\"##PORT##\"></TD></TR>\n\
		<TR><TD>Serverip:</TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
		<TR><TD>Suppress cmd08:</TD><TD><input name=\"suppresscmd08\" type=\"checkbox\" value=\"1\" ##SUPPRESSCMD08##></TD></TR>\n\
		<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLCONFIGCAMD35TCP "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"camd35tcp\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Camd35 TCP Config</TH></TR>\n\
		<TR><TD>Port:</TD><TD><input name=\"port\" type=\"text\" size=\"50\" maxlength=\"100\" value=\"##PORT##\"></TD></TR>\n\
		<TR><TD>Serverip:</TD><TD><input name=\"serverip\" type=\"text\" size=\"30\" maxlength=\"30\" value=\"##SERVERIP##\"></TD></TR>\n\
    	<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLCONFIGSERIAL "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"serial\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit Serial Config</TH></TR>\n\
		##DEVICES##\
		<TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
<BR><BR>\n\
##TPLFOOTER##"

#define TPLCONFIGSERIALDEVICEBIT "\
	<TR><TD>Device:</TD><TD><input name=\"device\" type=\"text\" size=\"50\" maxlength=\"100\" value=\"##SERIALDEVICE##\"></TD></TR>\n"

#ifdef HAVE_DVBAPI
#define TPLCONFIGDVBAPI "\
##TPLHEADER##\
##TPLMENU##\n\
##TPLCONFIGMENU##\n\
<BR><BR>\n\
##MESSAGE##\
<form action=\"config.html\" method=\"get\">\n\
	<input name=\"part\" type=\"hidden\" value=\"dvbapi\">\n\
	<input name=\"action\" type=\"hidden\" value=\"execute\">\n\
	<input name=\"enabled\" type=\"hidden\" value=\"0\">\n\
	<input name=\"au\" type=\"hidden\" value=\"0\">\n\
	<TABLE class=\"config\" cellspacing=\"0\">\n\
		<TR><TH>&nbsp;</TH><TH>Edit DVB Api Config</TH></TR>\n\
		<TR><TD>Enabled:</TD><TD><input name=\"enabled\" type=\"checkbox\" value=\"1\" ##ENABLEDCHECKED##>\n\
		<TR><TD>AU:</TD><TD><input name=\"au\" type=\"checkbox\" value=\"1\" ##AUCHECKED##>\n\
		<TR><TD>Boxtype:</TD><TD><SELECT name=\"boxtype\">##BOXTYPE##</select></TD></TR>\n\
		<TR><TD>User:</TD><TD><input name=\"user\" type=\"text\" size=\"20\" maxlength=\"20\" value=\"##USER##\"></TD></TR>\n\
		<TR><TD>PMT Mode:</TD><TD><select name=\"pmt_mode\">\n\
			<option value=\"0\" ##PMTMODESELECTED0##>0 - use camd.socket and PMT file</option>\n\
			<option value=\"1\" ##PMTMODESELECTED1##>1 - disable reading PMT file</option>\n\
			<option value=\"2\" ##PMTMODESELECTED2##>2 - disable camd.socket</option>\n\
			<option value=\"3\" ##PMTMODESELECTED3##>3 - read PMT file on startup only</option>\n\
		</SELECT></TD></TR>\n\
		<TR><TD>Priority:</TD>   <TD><textarea name=\"priority\"    cols=\"98\" rows=\"4\" class=\"bt\">##PRIORITY##</textarea></TD></TR>\n\
		<TR><TD>Ignore:</TD>     <TD><textarea name=\"ignore\"      cols=\"98\" rows=\"4\" class=\"bt\">##IGNORE##</textarea></TD></TR>\n\
		<TR><TD>Cw_delay:</TD><TD><input name=\"cw_delay\" type=\"text\" size=\"100\" maxlength=\"200\" value=\"##CWDELAY##\"></TD></TR>\n\
    <TR><TD colspan=\"2\" align=\"right\"><input type=\"submit\" value=\"OK\" ##BTNDISABLED##>\n</TD></TR>\n\
	</TABLE>\n\
</form>\n\
##TPLFOOTER##"
#endif

#define TPLSERVICECONFIGLIST "\
  ##TPLHEADER##\
  ##TPLMENU##\n\
  ##MESSAGE##\
  <BR><BR>\
  <TABLE cellspacing=\"0\" cellpadding=\"10\">\n\
    <TR>\n\
      <TH>Label</TH>\n\
      <TH colspan=\"3\" align=\"center\">Action</TH>\n\
    </TR>\n\
    ##SERVICETABS##\
    <TR>\n\
      <FORM action=\"services_edit.html\" method=\"get\"><INPUT TYPE=\"hidden\" NAME=\"action\" VALUE=\"add\">\n\
      <TD>New Service:</TD>\n\
      <TD><input name=\"service\" type=\"text\"></TD>\n\
      <TD  colspan=\"2\" align=\"center\"><input type=\"submit\" value=\"Add\" ##BTNDISABLED##></TD>\n\
      </FORM>\n\
    <TR>\n\
  </TABLE>\n\
  ##TPLFOOTER##"

#define TPLSERVICECONFIGLISTBIT "\
  <TR>\n\
    <TD>##LABEL##</TD>\n\
    <TD width =\"250\" align=\"center\">##SIDLIST##</TD>\n\
    <TD><A HREF=\"services_edit.html?service=##LABELENC##&action=edit\" TITLE=\"Edit this Service\"><IMG SRC=\"##EDIICO##\" BORDER=\"0\" ALT=\"Edit Service\"/></A></TD>\n\
    <TD><A HREF=\"services.html?service=##LABELENC##&action=delete\" TITLE=\"Delete this Service\"><IMG SRC=\"##DELICO##\" BORDER=\"0\" ALT=\"Delete Service\"/></A></TD>\n\
  </TR>\n"

#define TPLSERVICECONFIGSIDBIT "\
	<DIV class=\"##SIDCLASS##\">##SID##</DIV>"

#define TPLSERVICEEDIT "\
##TPLHEADER##\
##TPLMENU##\n\
##MESSAGE##\
<BR><BR>\n\
  <form action=\"services_edit.html\" method=\"get\">\n\
  <input name=\"service\" type=\"hidden\" value=\"##LABELENC##\">\n\
  <TABLE cellspacing=\"0\">\n\
    <TR>\n<TH>&nbsp;</TH>\n<TH>Edit Service ##LABEL##</TH>\n</TR>\n\
    <TR>\n<TD>caid: </TD><TD><input name=\"caid\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##CAIDS##\"></TD></TR>\
    <TR>\n<TD>provid: </TD><TD><input name=\"provid\" type=\"text\" size=\"50\" maxlength=\"50\" value=\"##PROVIDS##\"></TD></TR>\
    <TR>\n<TD>srvid: </TD><TD><textarea name=\"srvid\" cols=\"80\" rows=\"5\">##SRVIDS##</textarea></TD></TR>\
    <TR>\n<TD>&nbsp;</TD><TD align=\"right\"><input type=\"submit\" name=\"action\" value=\"Save\" title=\"Save service and reload services\" ##BTNDISABLED##></TD>\n\
  </TABLE>\n\
</form>\n\
##TPLFOOTER##"

#define TPLPRESHUTDOWN "\
##TPLHEADER##\
##TPLMENU##\n\
<br><br><br><DIV class = \"warning\">Do you really want to shutdown oscam?<br>\
All users will become disconnected.<br>\
You will not be able to restart oscam from the webinterface.<br>\
The webinterface will try to connect to oscam once 30 seconds after shutdown.</b><br>\n\
</DIV><br><form action=\"shutdown.html\" method=\"get\">\n\
<input type=\"submit\" name=\"action\" value=\"Shutdown\" title=\"Save service and reload services\" ##BTNDISABLED##></TD>\n\
</form>\
##TPLFOOTER##"

#define TPLSHUTDOWN "\
<HTML>\n\
  <HEAD>\n\
    <TITLE>OSCAM ##CS_VERSION## build ###CS_SVN_VERSION##</TITLE>\n\
    <link href=\"##ICO##\" rel=\"icon\" type=\"image/x-icon\"/>\
    ##REFRESH##\
    <style type=\"text/css\">\n\
    ##STYLESHEET##\n\
    </style>\n\
  </HEAD>\n\
  <BODY>\n\
    <H2>OSCAM ##CS_VERSION## build ###CS_SVN_VERSION##</H2>\
##TPLMENU##\n\
<br><P CLASS=\"blinking\">Oscam Shutdown - Try Reconnect in ##SECONDS## Seconds</p><br><br>\n\
##TPLFOOTER##"

#define TPLSCRIPT "\
##TPLHEADER##\
##TPLMENU##\n\
##MESSAGE##\
<br><br><b>Oscam execute script: ##SCRIPTNAME## --> Status: ##SCRIPTRESULT## --> Returncode: ##CODE##</b><br>\n\
##TPLFOOTER##"

enum refreshtypes {REFR_ACCOUNTS, REFR_READERS, REFR_SERVER, REFR_ANTICASC, REFR_SERVICES};

char *tpl[]={
	"HEADER",
	"FOOTER",
	"MENU",
	"REFRESH",
	"STATUS",
	"CLIENTSTATUSBIT",
	"USERCONFIGLIST",
	"ADDNEWUSER",
	"USERCONFIGLISTBIT",
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
#endif
#ifdef CS_ANTICASC
	,"USEREDITANTICASC"
	,"CONFIGANTICASC"
	,"CONFIGMENUANTICASC"
	,"FILEMENUANTICASC"
#endif
#ifdef CS_WITH_GBOX
	,"CONFIGMENUGBOX"
	,"READERCONFIGGBOXBIT"
#endif
#ifdef CS_WITH_DOUBLECHECK
	,"DOUBLECHECKBIT"
#endif
};

char *tplmap[]={
	TPLHEADER,
	TPLFOOTER,
	TPLMENU,
	TPLREFRESH,
	TPLSTATUS,
	TPLCLIENTSTATUSBIT,
	TPLUSERCONFIGLIST,
	TPLADDNEWUSER,
	TPLUSERCONFIGLISTBIT,
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
#endif
#ifdef CS_ANTICASC
	,TPLUSEREDITANTICASC
	,TPLCONFIGANTICASC
	,TPLCONFIGMENUANTICASC
	,TPLFILEMENUANTICASC
#endif
#ifdef CS_WITH_GBOX
	,TPLCONFIGMENUGBOX
	,TPLREADERCONFIGGBOXBIT
#endif
#ifdef CS_WITH_DOUBLECHECK
	,TPLDOUBLECHECKBIT
#endif
};

struct templatevars {
	int varscnt;
	int varsalloc;
	int tmpcnt;
	int tmpalloc;
	char **names;
	char **values;
	char **tmp;
};

struct uriparams {
	int paramcount;
	char *params[MAXGETPARAMS];
	char *values[MAXGETPARAMS];
};

static char hex2ascii[256][2];
static char noncekey[33];


char *tpl_addVar(struct templatevars *vars, int append, char *name, char *value);
char *tpl_addTmp(struct templatevars *vars, char *value);
char *tpl_printf(struct templatevars *vars, int append, char *varname, char *fmtstring, ...);
char *tpl_getVar(struct templatevars *vars, char *name);
struct templatevars *tpl_create();
void tpl_clear(struct templatevars *vars);
char *tpl_getUnparsedTpl(const char* name);
char *tpl_getTpl(struct templatevars *vars, const char* name);
char *parse_auth_value(char *value);
void calculate_nonce(char *result, int resultlen);
int check_auth(char *authstring, char *method, char *path, char *expectednonce);
void send_headers(FILE *f, int status, char *title, char *extra, char *mime);
void send_css(FILE *f);
char *getParam(struct uriparams *params, char *name);
int tpl_saveIncludedTpls(const char *path);

