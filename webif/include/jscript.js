/* Function for refresh pages */
var oReloadTimer=null;var oCounterTimer=null;
function reloadDocument(){history.pushState('', document.title, window.location.pathname);window.location.reload();};
function reloadPause(){clearTimeout(oReloadTimer);};
function runReloadCounter(){var oReloadContent=document.getElementById("ReloadContent");if(oReloadContent){if(counter<0){counter=counterfull;}counter--;}};
function initDoc(){if(oReloadTimer)window.clearInterval(oReloadTimer);oReloadTimer=window.setInterval("reloadDocument();",counterfull*1000);if(oCounterTimer)window.clearInterval(oCounterTimer);oCounterTimer=window.setInterval("runReloadCounter();",1000);};

/* Function for add new user in readers.html */
function addreader(){cdpause();document.getElementById("searchTable").style.display="none";document.getElementById("newreader").style.display="block";};

/* Function for add new reader in userconfig.html */
function adduser(){cdpause();document.getElementById("searchTable").style.display="none";document.getElementById("newuser").style.display="block";};

/* Function for searching in table - uncompressed */
function doSearch() {
	var searchText = document.getElementById('searchTerm').value;
	var targetTable = document.getElementById('dataTable');
	var targetTableColCount;

	//Loop through table rows
	for (var rowIndex = 0; rowIndex < targetTable.rows.length; rowIndex++) {
		var rowData = '';
		//Get column count from header row
		if (rowIndex == 0 || rowIndex==1) {
			targetTableColCount = targetTable.rows.item(rowIndex).cells.length;
			continue; //do not execute further code for header row.
		}

		//Process data rows. (rowIndex >= 1)
		for (var colIndex = 0; colIndex < targetTableColCount; colIndex++) {
			var cellText = '';
			if (navigator.appName == 'Microsoft Internet Explorer')
				cellText = targetTable.rows.item(rowIndex).cells.item(colIndex).innerText;
			else
			cellText = targetTable.rows.item(rowIndex).cells.item(colIndex).textContent;

			rowData += cellText;
		}

		// Make search case insensitive.
		rowData = rowData.toLowerCase();
		searchText = searchText.toLowerCase();

		//If search term is not found in row data
		//then hide the row, else show
		if (rowData.indexOf(searchText) == -1)
			targetTable.rows.item(rowIndex).style.display = 'none';
		else
			targetTable.rows.item(rowIndex).style.display = 'table-row';
		}
	}

/* Functions for sorting in table - uncompressed */
var TINY={};

function T$(i){return document.getElementById(i)}
function T$$(e,p){return p.getElementsByTagName(e)}

TINY.table=function(){
	function sorter(n,t,p){this.n=n; this.id=t; this.p=p; if(this.p.init){this.init()}}
	sorter.prototype.init=function(){
		this.set(); var t=this.t, i=d=0; t.h=T$$('tr',t)[1];
		t.l=t.r.length; t.w=t.r[0].cells.length; t.a=[]; t.c=[];
		if(this.p.colddid){
			d=T$(this.p.colddid);
			var o = document.createElement('option');
			o.value = -1; 
            o.innerHTML = 'All Columns'; 
            d.appendChild(o)
		}
		for(i;i<t.w;i++){
			var c=t.h.cells[i]; t.c[i]={};
			if(c.className!='nosort'){
			    c.className = this.p.headclass; 
                c.onclick=new Function(this.n+'.sort('+i+')');
				c.onmousedown=function(){return false};
			}
			if(this.p.columns){
				var l=this.p.columns.length, x=0;
				for(x;x<l;x++){
					if(this.p.columns[x].index==i){
						var g=this.p.columns[x];
						t.c[i].format=g.format==null?1:g.format; t.c[i].decimals=g.decimals==null?2:g.decimals
					}
				}
			}
			if(d){
			    var o = document.createElement('option');
			    o.value = i; o.innerHTML = T$$('h3', c)[0].innerHTML; 
                d.appendChild(o)
			}
		}
		this.reset()
	};
	sorter.prototype.reset=function(){
		var t=this.t; t.t=t.l;
		for(var i=0;i<t.l;i++){t.a[i]={}; t.a[i].s=1}
		if(this.p.sortcolumn!=undefined){
			this.sort(this.p.sortcolumn,1,this.p.is)
		}
	};
	sorter.prototype.sort=function(x,f,z){
		var t=this.t; t.y=x; var x=t.h.cells[t.y], i=0, n=document.createElement('tbody');
		for(i;i<t.l;i++){
			t.a[i].o=i; var v=t.r[i].cells[t.y]; t.r[i].style.display='';
			while(v.hasChildNodes()){v=v.firstChild}
			t.a[i].v=v.nodeValue?v.nodeValue:''
		}
		for(i=0;i<t.w;i++){var c=t.h.cells[i]; if(c.className!='nosort'){c.className=this.p.headclass}}
		if(t.p==t.y&&!f){t.a.reverse(); x.className=t.d?this.p.ascclass:this.p.descclass; t.d=t.d?0:1}
		else{t.p=t.y; f&&this.p.sortdir==-1?t.a.sort(cp).reverse():t.a.sort(cp); t.d=0; x.className=this.p.ascclass}
		for(i=0;i<t.l;i++){var r=t.r[t.a[i].o].cloneNode(true); n.appendChild(r)}
		t.replaceChild(n,t.b); this.set();
	};
	sorter.prototype.set=function(){
		var t=T$(this.id); t.b=T$$('tbody',t)[0]; t.r=t.b.rows; this.t=t
	};
	function decimals(n,d){return Math.round(n*Math.pow(10,d))/Math.pow(10,d)};
	function cp(f,c){
		var g,h; f=g=f.v.toLowerCase(); c=h=c.v.toLowerCase();
		var i=parseFloat(f.replace(/(\$|\,)/g,'')), n=parseFloat(c.replace(/(\$|\,)/g,''));
		if(!isNaN(i)&&!isNaN(n)){g=i,h=n}
		i=Date.parse(f); n=Date.parse(c);
		if(!isNaN(i)&&!isNaN(n)){g=i; h=n}
		return g>h?1:(g<h?-1:0)
	};
	return{sorter:sorter}
}();
