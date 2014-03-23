var oReloadTimer=null;var oCounterTimer=null;
function reloadDocument(){history.pushState('', document.title, window.location.pathname);window.location.reload();};
function cdpause(){clearTimeout(oReloadTimer);};
function runReloadCounter(){var oReloadContent=document.getElementById("ReloadContent");if(oReloadContent){if(counter<0){counter=counterfull;}counter--;}};
function initDoc(){if(oReloadTimer)window.clearInterval(oReloadTimer);oReloadTimer=window.setInterval("reloadDocument();",counterfull*1000);if(oCounterTimer)window.clearInterval(oCounterTimer);oCounterTimer=window.setInterval("runReloadCounter();",1000);};
function gotosite(Action){window.location.href=Action;}

/* Function for add new reader in readers.html */
function addreader(){cdpause();document.getElementById("searchTable").style.display="none";document.getElementById("newreader").style.display="block";};

/* Function for add new user in userconfig.html */
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

/* Functions for sorting in table - uncompressed
 * Original script on http://1.s3.envato.com/files/53734448/index.html
 */
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

String.prototype.toHHMMSS = function () {
	if(this.length < 1){
		return ''
	}
    var sec_num = parseInt(this, 10); // don't forget the second param
    var hours   = Math.floor(sec_num / 3600);
    var minutes = Math.floor((sec_num - (hours * 3600)) / 60);
    var seconds = sec_num - (hours * 3600) - (minutes * 60);

    if (hours   < 10) {hours   = "0" + hours;}
    if (minutes < 10) {minutes = "0" + minutes;}
    if (seconds < 10) {seconds = "0" + seconds;}
    var time    = hours + ':' + minutes + ':' + seconds;
    return time;
}

function runden(value) {
	var k = (Math.round(value * 100) / 100).toString();
	k += (k.indexOf('.') == -1)? '.00' : '00';
	return k.substring(0, k.indexOf('.') + 3);
}


/*
 * General: Eventhandler
 */
$(function(){
	// Pollinterval UP
	$("#inc").click(function(){
		if(pollintervall > 98000) return;
		$(":text[name='pintervall']").val( Number($(":text[name='pintervall']").val()) + 1 );
		pollintervall = $(":text[name='pintervall']").val() * 1000;
		if(!nostorage){
			sessionStorage.pollintervall = pollintervall;
		}
	});
	// Pollinterval DOWN
	$("#dec").click(function(){
		if(pollintervall < 2000) return;
		$(":text[name='pintervall']").val( Number($(":text[name='pintervall']").val()) - 1 );
		pollintervall = $(":text[name='pintervall']").val() * 1000;
		if(!nostorage){
			sessionStorage.pollintervall = pollintervall;
		}
	});
	// Hover for showing Chart on Statuspage
	$('table.status').on('mouseover', 'tr > td.statuscol14', function(e){
		var uid = '#' + $( this ).parent().attr('id');
		if( 'pcr'.indexOf($( uid ).attr('class')) >= 0 ){
			if($( uid ).attr('data-ref').length){
				$('#charthead').text($( uid + ' > td:nth-child(3) > a:nth-child(1)').text() + ' History');
				$( "#graph" ).html('');
				var arry = $( uid ).attr('data-ref').split(",");
				$.each(arry, function( index, value ) {
					$( "#graph" ).append(generateBar(value));
				});
				$( "#chart" ).show();
			}
			$( "#chart" ).offset({left:e.pageX + 20,top:e.pageY - 20});
		}
	});
	// Mousout for hiding Chart on Statuspage
	$('table.status').on('mouseout', 'tr > td.statuscol14', function(){
		$( "#chart" ).hide();
	});

	$("#regexok").click(function(){

		for(var i = 1; i < 6; i++) {
			var pattern = $('#regex' + i).val();
			if (pattern) {
				var color = $('#color' + i).val();
				var fcolor = $('#fcolor' + i).val();
			} else {
				var color = '';
				var fcolor = '';
			}
			localStorage['regex' + i] = pattern?pattern:'';
			localStorage['color' + i] = color?color:'';
			localStorage['fcolor' + i] = fcolor?fcolor:'';
			localStorage['whitelisted' + i] = $('#whitelisted' + i).prop('checked')?'1':'0';
			localStorage['hidden' + i] = $('#hidden' + i).prop('checked')?'1':'0';
		}

	});

	$("#regexreset").click(function(){

		if (confirm('Delete all Filters and Colors?')) {
			for(var i = 1; i < 6; i++) {
				$('#regex' + i).val('');
				$('#whitelisted' + i).prop('checked', false);
				$('#hidden' + i).prop('checked', false);
				$('#color' + i).val('');
				$('#fcolor' + i).val('');
				localStorage['regex' + i] = '';
				localStorage['color' + i] = '';
				localStorage['fcolor' + i] = '';
				localStorage['whitelisted' + i] = '0';
				localStorage['hidden' + i] = '0';
			}
			$('li.regex > div.colorPicker-picker').css('background-color','#FFFFFF');
		}

	});
	
	$(".debugls a, .debugl a").click(function(){
		parameters = parameters + "&debug=" + $( this ).attr('sendval');
		return false;
	});
	
	$("#savelog").on('click', function (event) {
		var txt = '';
		$("#livelogdata li").each(function( i ) {
			txt += $(this).text() + '\n';
		});
		// Data URI
		txtData = 'data:application/txt;charset=utf-8,' + encodeURIComponent(txt);
		$(this).attr({'href': txtData,	'target': '_blank'});
	});

});


/*
 * Userpage Functions: Update Page
 */
function updateUserpage(data) {

	// show heartbeat
	var orgstyle = $( "input.pintervall" ).css("background-color");
	$( "input.pintervall" ).css("background-color",$( "#picolor" ).css("background-color"));

	// update user lines
	$.each(data.oscam.users, function(i, item) {
		var uid = "#" + item.user.usermd5;

		switch (item.user.classname) {
			case 'online':
			$( uid ).attr('class', item.user.classname);
			$( uid + " td.usercol2").attr( 'title', 'SLEEP: ' + item.user.stats.expectsleep );
			$( uid + " td.usercol2").html( "<B>" + item.user.status + "</B><br>" + item.user.ip);
			$( uid + " td.usercol3").html( item.user.stats.idle + "<br>" + item.user.stats.timeonchannel.toHHMMSS());

			if(item.user.protoicon.length > 0){
				if($( uid + " td.usercol4").html().length == 0 ) {
					var protoimage = $('<img class="protoicon" src="image?i=IC_' + item.user.protoicon + '" />');
					protoimage.hide();
					$( uid + " td.usercol4" ).prepend(protoimage);
					protoimage.fadeIn('slow');
				}
			} else {
				$( uid + " td.usercol4").text( item.user.protocol );
			}

			$( uid + " td.usercol4").attr( 'title', item.user.prototitle );

			// channel icon
			$( uid + " td.usercol6").attr( 'title', item.user.lastchanneltitle );
			if(item.user.lca.length > 0){
				var image;
				if($( uid + " td.usercol6").html().length == 0 ) {
					image = $('<img class="usericon" src="image?i=IC_' + item.user.lca + '" />');
					image.hide();
					$( uid + " td.usercol6" ).prepend(image);
					image.fadeIn('slow');
				} else {
					image = $( uid + " td.usercol6 img.usericon");
					if(image.attr('src') != ('image?i=IC_' + item.user.lca)) {
						image.fadeOut('fast', function () {
							image.attr('src', 'image?i=IC_' + item.user.lca );
							image.fadeIn('slow');
						});
						image.attr('alt', item.user.lcb );
						image.attr('title', item.user.lastchanneltitle );
					}
				}
			} else {
				$( uid + " td.usercol6").html(item.user.lastchannel );
			}

			$( uid + " td.usercol7").text( item.user.stats.cwlastresptime + 'ms');
			//usercol8 ???
			$( uid + " td.usercol9").text( item.user.stats.cwok );
			$( uid + " td.usercol10").text( item.user.stats.cwnok );
			$( uid + " td.usercol11").text( item.user.stats.cwignore );
			$( uid + " td.usercol12").text( item.user.stats.cwtimeout );
			$( uid + " td.usercol13").text( item.user.stats.cwccyclechecked + ' / ' + item.user.stats.cwcycleok + ' / ' + item.user.stats.cwcyclenok + ' / ' + item.user.stats.cwcycleign );
			$( uid + " td.usercol14").text( item.user.stats.cwcache );
			$( uid + " td.usercol15").text( item.user.stats.cwtun );
			$( uid + " td.usercol16").text( item.user.stats.cwcache );
			$( uid + " td.usercol17").text( item.user.stats.emmok );
			$( uid + " td.usercol18").text( item.user.stats.emmnok );
			$( uid + " td.usercol19").text( item.user.stats.cwrate + item.user.stats.cwrate2 );
			$( uid + " td.usercol22").text( item.user.stats.cascusercomb );
			$( uid + " td.usercol21").text( item.user.stats.n_requ_m );
			$( uid + " td.usercol20").attr( 'title', item.user.expview );
			$( uid + " td.usercol20").text( item.user.stats.expdate );
			break;

			case 'connected':
			$( uid ).attr('class', item.user.classname);
			$( uid + " td.usercol2").attr( 'title', 'SLEEP: ' );
			$( uid + " td.usercol2").html( "<B>" + item.user.status + "</B><br>" + item.user.ip);
			$( uid + " td.usercol3").html( item.user.stats.idle + "<br>" + item.user.stats.timeonchannel.toHHMMSS());

			if(item.user.protoicon.length > 0){
				if($( uid + " td.usercol4").html().length == 0 ) {
					var protoimage = $('<img class="protoicon" src="image?i=IC_' + item.user.protoicon + '" />');
					protoimage.hide();
					$( uid + " td.usercol4" ).prepend(protoimage);
					protoimage.fadeIn('slow');
				}
			} else {
				$( uid + " td.usercol4").text( item.user.protocol );
			}

			$( uid + " td.usercol4").attr( 'title', item.user.prototitle );

			// channel icon
			$( uid + " td.usercol6").attr( 'title', item.user.lastchanneltitle );
			if(item.user.lca.length > 0){
				var image;
				if($( uid + " td.usercol6").html().length == 0 ) {
					image = $('<img class="usericon" src="image?i=IC_' + item.user.lca + '" />');
					image.hide();
					$( uid + " td.usercol6" ).prepend(image);
					image.fadeIn('slow');
				} else {
					image = $( uid + " td.usercol6 img.usericon");
					if(image.attr('src') != ('image?i=IC_' + item.user.lca)) {
						image.fadeOut('fast', function () {
							image.attr('src', 'image?i=IC_' + item.user.lca );
							image.fadeIn('slow');
						});
						image.attr('alt', item.user.lcb );
						image.attr('title', item.user.lastchanneltitle );
					}
				}
			} else {
				$( uid + " td.usercol6").html(item.user.lastchannel );
			}
			break;

			default:
			if($( uid ).attr('class') == 'online' || $( uid ).attr('class') == 'connected'){
				// last status was online so cleanup offline
				$( uid ).attr('class', item.user.classname);
				$( uid + " td.usercol2").attr( 'title', 'SLEEP: ');
				$( uid + " td.usercol2").html( item.user.status );
				$( uid + " td.usercol3").text( '' );
				$( uid + " td.usercol7").text( '0' );
				$( uid + " td.usercol4").text( '' );
				$( uid + " td.usercol4").attr( 'title', '' );
				var protoimage = $( uid + " td.usercol4 img.protoicon");
				if(image){
					protoimage.fadeOut('slow');
					protoimage.remove();
				}

				//channelicon
				$( uid + " td.usercol6").text( '' );
				var image = $( uid + " td.usercol6 img.usericon");
				if(image){
					image.fadeOut('slow');
					image.remove();
				}
			}
			break;
		}
	});

	// update user totals
	$( "#tot_users" ).html( data.oscam.totals.usertotal );
	$( "#tot_disabled" ).html( data.oscam.totals.userdisabled );
	$( "#tot_expired" ).html( data.oscam.totals.userexpired );
	$( "#tot_active" ).html( data.oscam.totals.useractive );
	$( "#tot_connected" ).html( data.oscam.totals.userconnected );
	$( "#tot_online" ).html( data.oscam.totals.useronline );

	// update result totals
	$( "#tot_cwok" ).html( data.oscam.totals.cwok + " (" + data.oscam.totals.cwok_rel + "%)");
	$( "#tot_cwcache" ).html( data.oscam.totals.cwcache + " (" + data.oscam.totals.cwcache_rel + "%)");
	$( "#tot_cwnok" ).html( data.oscam.totals.cwnok + " (" + data.oscam.totals.cwnok_rel + "%)");
	$( "#tot_cwtout" ).html( data.oscam.totals.cwtimeout + " (" + data.oscam.totals.cwtimeout_rel + "%)");
	$( "#tot_cwign" ).html( data.oscam.totals.cwignore + " (" + data.oscam.totals.cwignore_rel + "%)");
	$( "#tot_ecmmin" ).html( data.oscam.totals.ecm_min );
	$( "#tot_cw" ).html( data.oscam.totals.tot_cw );
	var cwpos = parseInt(data.oscam.totals.cwok) + parseInt(data.oscam.totals.cwcache);
	var cwpos_rel = runden(parseFloat(data.oscam.totals.cwok_rel) + parseFloat(data.oscam.totals.cwcache_rel));
	$( "#tot_cwpos" ).html( "<B>Total OK:  </B> "+ cwpos + " (" + cwpos_rel + "%)");
	var cwneg = parseInt(data.oscam.totals.cwnok) + parseInt(data.oscam.totals.cwtimeout);
	var cwneg_rel = runden(parseFloat(data.oscam.totals.cwnok_rel) + parseFloat(data.oscam.totals.cwtimeout_rel));
	$( "#tot_cwneg" ).html( "<B>Total NOK:  </B> "+ cwneg + " (" + cwneg_rel + "%)");

	// update footer
	$( "#curtime" ).text( ' ' + data.oscam.curdate + ' | ' + data.oscam.curtime + ' ' );
	$( "#uptime" ).text( data.oscam.uptimefmt );

	// hide heartbeat
	setTimeout(function (){$( "input.pintervall" ).css("background-color",orgstyle);}, 300);
}

/*
 * Readerpage Functions: Update Page
 */
function updateReaderpage(data) {

	// show heartbeat
	var orgstyle = $( "input.pintervall" ).css("background-color");
	$( "input.pintervall" ).css("background-color",$( "#picolor" ).css("background-color"));

	// update reader lines
	$.each(data.oscam.readers, function(i, item) {
		var uid = "#" + item.labelmd5;

		$( uid ).attr('class', item.classname);

		$( uid + " td.readercol4").text(item.stats.ecmsok);
		$( uid + " td.readercol5").text(item.stats.ecmsnok);
		$( uid + " td.readercol6").text(item.stats.ecmsfiltered);
		$( uid + " td.readercol7").text(item.stats.emmerror);
		$( uid + " td.readercol8").text(item.stats.emmwritten);
		$( uid + " td.readercol9").text(item.stats.emmskipped);
		$( uid + " td.readercol10").text(item.stats.emmblocked);
		$( uid + " td.readercol11").text(item.stats.lbweight);

	});

	// update footer
	$( "#curtime" ).text( ' ' + data.oscam.curdate + ' | ' + data.oscam.curtime + ' ' );
	$( "#uptime" ).text( data.oscam.uptimefmt );

	// hide heartbeat
	setTimeout(function (){$( "input.pintervall" ).css("background-color",orgstyle);}, 300);
}

/*
 *  LiveLog Functions: format the debuglevel switcher
 */
function setDebuglevel(debug, maxdebug) {
	var cs_dblevel = parseInt(debug);
	var maxlevel = parseInt(maxdebug);
	if(lastdebuglevel != cs_dblevel) {
		var lvl = 0;
		$("#debugfrom").text(' Switch Debug from ' + cs_dblevel + ' to ');
		for( var i = 0; i < maxlevel; i++){
			lvl = 1 << i;
			if(cs_dblevel & lvl){
				$("#debug" + lvl).attr('sendval', cs_dblevel - lvl);
			} else {
				$("#debug" + lvl).attr('sendval', cs_dblevel + lvl);
			}
			$("#debug" + lvl).attr('class', (cs_dblevel & lvl)?'debugls':'debugl');
		}
		lastdebuglevel = cs_dblevel;
	}
}

/*
 * Livelog Functions: get filter color
 */
function getLogColor(text){

	if(nostorage){
		return null;
	}
	
	for(var i = 1; i < 6; i++) {
		var pattern = localStorage['regex' + i];
		var color = localStorage['color' + i];
		var fcolor = localStorage['fcolor' + i];
		var hidden = localStorage['hidden' + i];
		var regex = new RegExp(pattern);
		if(pattern && (pattern != '') && (regex.exec(text))){
			return {
				color : color,
				fcolor : fcolor,
				hidden : hidden
			}
		}
	}
	return null;
}

/*
 * Livelog Functions: get whitelist state
 */
function isWhitelisted(text){
	
	if(nostorage){
		return 1;
	}
	
	var numwhite = 0;
	for(var i = 1; i < 6; i++) {
		numwhite += parseInt(localStorage['whitelisted' + i]);
	}
	if(numwhite > 0){
		for(var i = 1; i < 6; i++) {
			var whitelisted = localStorage['whitelisted' + i];
			var pattern = localStorage['regex' + i];
			var regex = new RegExp(pattern);
			if(pattern && (pattern != '') && (whitelisted == '1') && (regex.exec(text)) ){	
				return 1;
			}
		}
		return 0;
	} else {
		return 1;
	}
}

/*
 * LiveLog Functions: manage the delivered data / loglines
 */
function updateLogpage(data) {

	if(data.oscam.debug){
		setDebuglevel(data.oscam.debug, data.oscam.maxdebug);
	}
	if(data.oscam.logdisabled){
		stoppoll = 1;
		$("#livelogdata").append('<li>Log is disabled</li>\n');
	}

	$.each(data.oscam.lines, function(i, item) {

		if ( isWhitelisted( item.line ) ){
			var newcolor = getLogColor(item.line);
			var newline = $('<li class="' + item.usr + '">' + item.line + '</li>\n');
			var hiddenline = 0;
			if(newcolor){
				if(newcolor.hidden != '1'){
					if(newcolor.color && newcolor.color != ''){
						newline.css('background-color', newcolor.color);
					}
					if(newcolor.fcolor && newcolor.fcolor != ''){
						newline.css('color', newcolor.fcolor);
					}
					$("#livelogdata").append(newline);
				} else {
					hiddenline = 1;
				}
			} else {
				$("#livelogdata").append(newline);
			}

			if(!hiddenline){
				if ($("#livelogdata li").length >= maxloglines) {
					$("#livelogdata li").eq(0).remove();
				}
				if ($("#livelog:hover").length) {
					$('#livelog').stop(true);
				} else {
					$("#livelog").scrollTop($("#livelog").prop("scrollHeight"));
				}
			}

		}
		parameters = "?lasttime=" + item.ts;

	});

	// update footer
	$( "#curtime" ).text( ' ' + data.oscam.curdate + ' | ' + data.oscam.curtime + ' ' );
	$( "#uptime" ).text( data.oscam.uptimefmt );

}

/*
 * Statuspage Functions: JQuery Extensions
 */
jQuery.fn.toHtmlString = function () {
	return $('<td></td>').html($(this).clone()).html();
};

/*
 *  Statuspage Functions: Generate a Bar for Barchart
 */
function generateBar(value){
    var bar = $('<div class="bar"/>');
    var maxheight = 75; //$( "#graph" ).height() -15;
    var numval = parseInt(value);
    numval = Math.floor(numval / 30);
    if(numval >= maxheight){
        bar.css('background-color', '#FF0000');
        numval = maxheight;
    }
    bar.css('height', numval + 'px');
    return bar;
}

/*
 *  Statuspage Functions: Add/Remove Subhedline
 */
function addremoveSubheadline(remove, data) {

	if(remove == 1 && $("#clientsubheadline").length) {
		$("#clientsubheadline").fadeOut('slow');
		$("#clientsubheadline").remove();
	}

	if(remove == 0 && ! $("#clientsubheadline").length){
		var strheadline = '<TR id="clientsubheadline"><TD CLASS="subheadline" COLSPAN="11">';
		if (data.oscam.status.ucac == '0') { //hide idle clients
			strheadline += '<P>Clients <span id="ucs">' + data.oscam.status.ucs + '</span>/<span id="uca">' + data.oscam.status.uca + '</span></P></TD>'
		} else {
			strheadline += '<P>Clients <span id="ucs">' + data.oscam.status.ucs + '</span>/<span id="uca">' + data.oscam.status.uca + '</span> (<span id="ucac">' + data.oscam.status.ucac + '</span> with ECM within last <span id="cfgh">' + data.oscam.status.cfgh + '</span> seconds)</P></TD>'
		}
		strheadline += '<TD CLASS="subheadline"><form name="gotoform" method="post" action=""><select size="1" onChange="gotosite(this.value)">';
		strheadline += '<option value="">-- select Action --</option><option value="status.html?hideidle=5">Show Hidden User</option>';
		strheadline += '<option value="status.html?hideidle=0">Show Idle User</option><option value="status.html?hideidle=1">Hide Idle User</option>';
		strheadline += '</select></form></TD></TR>';
		var headline = $(strheadline);
		headline.hide();
		$('table.status').append(headline);
		headline.fadeIn('slow');
	}
}

/*
 *  Statuspage Functions: Update Page
 */
function updateStatuspage(data){

	// show heartbeat
	var orgstyle = $( "input.pintervall" ).css("background-color");
	$( "input.pintervall" ).css("background-color",$( "#picolor" ).css("background-color"));

	var updatedclients="";
	var cardokreader = 0;
	var connectedproxys = 0;
	// update status lines
	$.each(data.oscam.status.client, function(i, item) {
		if (item.connection.status == 'CARDOK') cardokreader++;
		if (item.connection.status == 'CONNECTED') connectedproxys++;
		var newrow;
		if(item.type == "c") {
			updatedclients += item.thid + ",";
		}

		var uid = "#" + item.thid;
		//console.log(updatedclients);

		if( ! $( uid ).length && item.type == "c") {
			//build new row
			var rowcontent = '<TR ID="' + item.thid + '"><TD CLASS="statuscol0"/><TD CLASS="statuscol1"/><TD CLASS="statuscol4"/>';
			rowcontent += '<TD CLASS="statuscol5"/><TD CLASS="statuscol7"/><TD CLASS="statuscol8"/><TD CLASS="statuscol9"/>';
			rowcontent += '<TD CLASS="statuscol12"/><TD CLASS="statuscol13"/><TD CLASS="statuscol14"/><TD CLASS="statuscol15"/>';
			rowcontent += '<TD CLASS="statuscol16"/></TR>';
			newrow = $(rowcontent);
			newrow.hide();
			// if we have no clients we have to add the headline first
			if($("tr.c").length == 0){addremoveSubheadline(0, data);}
			// append new clientrow to table
			$('table.status').append(newrow);
			$( uid + " > td.statuscol0").append('<a title="Hide this User" href="status.html?hide=' + item.thid + '"><img class="icon" alt="Hide User" src="image?i=ICHID"></img>');
			$( uid + " > td.statuscol1").append('<a title="Kill this User ' + item.name + '" href="status.html?action=kill&threadid=' + item.thid + '"><img class="icon" alt="Kill this User ' + item.name + '" src="image?i=ICKIL"></img>');

			if(data.oscam.piconenabled == "1" && item.protoicon){
				$( uid + " > td.statuscol9").append('<img class="protoicon" title="'+item.protocolext+'" alt="'+item.protocolext+'" src="image?i=IC_' + item.protoicon + '"></img>');
			} else {
				$( uid + " > td.statuscol9").text(item.protocol);
			}
			if (data.oscam.piconenabled == "1" && !item.upicmissing){
				$( uid + " > td.statuscol4").append('<a href="user_edit.html?user=' + item.name_enc + '"><img class="statususericon" title="Edit User: ' + item.name + item.desc + '" src="image?i=IC_' + item.name_enc + '"></img></a>');
			} else {
				$( uid + " > td.statuscol4").append('<a href="user_edit.html?user=' + item.name_enc + '" title="Edit User: ' + item.name + item.desc + item.upicmissing + '">' + item.name + '</a>');
			}
			$( uid + " > td.statuscol13").append('<A HREF="files.html?file=oscam.srvid" TITLE="' + item.request + '"/>');
		}

		$( uid ).attr({	'class': item.type,
						'data-ref': item.request.ecmhistory })
						.removeAttr('style');

		// fix for anonymous newcamd-clients
		if ($(uid + " > td.statuscol4").text().match('anonymous')) {
			if(data.oscam.piconenabled == "1" && item.protoicon){
				$( uid + " > td.statuscol9").html('<img class="protoicon" title="' + item.protocolext + '" alt="' + item.protocolext + '" src="image?i=IC_' + item.protoicon + '"></img>');
			} else {
				$( uid + " > td.statuscol9").text(item.protocol);
			}
			if(data.oscam.piconenabled == "1" && !item.upicmissing){
				$( uid + " > td.statuscol4").html('<a href="user_edit.html?user=' + item.name_enc + '"><img class="statususericon" title="Edit User: ' + item.name + item.desc + '" src="image?i=IC_' + item.name_enc + '"></img></a>');
			} else {
				$( uid + " > td.statuscol4").html('<a href="user_edit.html?user=' + item.name_enc + '" title="Edit User: ' + item.name + item.desc + item.upicmissing + '">' + item.name + '</a>');
			}
		}

		switch (item.au) {
			case '0':
				$( uid + " > td.statuscol5").text('OFF');
			break;
			case '-1':
				$( uid + " > td.statuscol5").html('<a class="tooltip" href="#">ON<span>' + item.aufmt + '</span></a>');
			break;
			default:
				$( uid + " > td.statuscol5").html('<a class="tooltip" href="#">ACTIVE<span>' + item.aufmt + '</span></a>');
			break;
		}

		$( uid + " > td.statuscol7").text(item.connection.ip);
		$( uid + " > td.statuscol8").text(item.connection.port);
		$( uid + " > td.statuscol9").attr('title', item.protocolext);
		$( uid + " > td.statuscol12").text(item.request.caid + ':' + item.request.srvid);

		var newimage;

		if (data.oscam.piconenabled == '1' && item.request.srvid != '0000' && item.request.picon){

			// if we already have a picon within link
			if($( uid + " > td.statuscol13 > a > img.statususericon" ).length){
				// we compare the picon name and switch if different
				var image = $( uid + " > td.statuscol13 > a > img.statususericon");
				if( image.attr('src') != 'image?i=IC_' + item.request.picon){
					// set title of link as tooltip
					$( uid + " > td.statuscol13 > a").attr('title', item.request.chprovider + item.request.chname);
					image.hide();
					image.attr('src', 'image?i=IC_' + item.request.picon);
					image.fadeIn('slow');
				}
			} else {
				// we have no image so we have to create one

				// if we have picon clear text
				$( uid + " > td.statuscol13").text('');

				// if we have no link we create one
				if(!$( uid + " > td.statuscol13 > a").length){
					$( uid + " > td.statuscol13").append('<a href="files.html?file=oscam.srvid"/>');
				}
				// set title of link as tooltip
				$( uid + " > td.statuscol13 > a").attr('title', item.request.chprovider + item.request.chname);

				// just to be sure that class of image is set
				if($( uid + " > td.statuscol13 > a > img" ).length){
					$( uid + " > td.statuscol13 > a > img" ).attr( 'class', 'statususericon' );
				}

				newimage = $('<img class="statususericon" src="image?i=IC_' + item.request.picon +'">');
				newimage.hide();
				$( uid + " > td.statuscol13 > a").append(newimage);
				newimage.fadeIn('slow');
			}

		} else {
			// picon is not delivered in JSON - we set the text of column
			if(item.request.chprovider && item.request.chname && item.request.srvid != '0000'){
				$( uid + " > td.statuscol13").html(item.request.chprovider + item.request.chname);
			} else {
				$( uid + " > td.statuscol13").html('');
			}
		}

		if(item.type == 'c'){
			$( uid + " > td.statuscol14").text(item.request.answered?item.request.answered + ' (' + item.request.msvalue + 'ms)':'');
		} else {
			if(item.request.lbvalue && item.request.lbvalue !='no data'){
				//console.log("LB for " +item.name+ " is "+ item.request.lbvalue);
				if(!$( uid + " > td.statuscol14 > a").length){
					$( uid + " > td.statuscol14")
						.text('')
						.append('<a href="readerstats.html?label="' + item.name + '"&amp;hide=4" TITLE="Show statistics for: ' + item.name + '">');
				}
				$( uid + " > td.statuscol14 > a").text(item.request.lbvalue);
			} else {
				$( uid + " > td.statuscol14").text('no data');
			}
		}

		$( uid + " > td.statuscol15")
			.text(item.times.loginfmt)
			.attr('title', 'Online: ' + item.times.online.toHHMMSS() + ' IDLE: ' + item.times.idle.toHHMMSS());

		// read entitlements and cccam-cards
		var $html = $( uid + " > td.statuscol16").toHtmlString();
		
		if ( $html != undefined ) {
			var buffer = $html.substring($html.indexOf('<br>'),$html.indexOf('</a>'));
		}
		
		$( uid + " > td.statuscol16").text(item.connection.status);
		
		if ( buffer ) {
			$( uid + " > td.statuscol16").append(buffer + '</a>');
		}

		if(newrow){
			newrow.fadeIn("slow");
		}

	});

	//remove non existing
	$("tr.c").each(function() {
		if(updatedclients.indexOf($(this).attr('id')) == -1){
			$(this).fadeOut('slow').remove();
		}
	});

	// if we have no clients left we remove the headline
	if($("tr.c").length == 0 && data.oscam.status.uca == '0'){
		addremoveSubheadline(1);
	}

	//update client-headline
	if(data.oscam.status.uca != '0'){
		$( "#ucs" ).text( data.oscam.status.ucs );
		$( "#uca" ).text( data.oscam.status.uca );
		if (data.oscam.status.ucac != '0') $( "#ucac" ).text( data.oscam.status.ucac );
	}
	//update reader-headline
	$( "#rcc" ).text( cardokreader );

	//update proxy-headline
	$( "#pcc" ).text( connectedproxys );

	// update footer
	$( "#curtime" ).text( ' ' + data.oscam.curdate + ' | ' + data.oscam.curtime + ' ' );
	$( "#uptime" ).text( data.oscam.uptimefmt );

	// sysinfos
	$( "#mem_cur_total" ).text( data.oscam.sysinfo.mem_cur_total );
	$( "#mem_cur_free" ).text( data.oscam.sysinfo.mem_cur_free );
	$( "#mem_cur_used" ).text( data.oscam.sysinfo.mem_cur_used );
	$( "#mem_cur_buff" ).text( data.oscam.sysinfo.mem_cur_buff );
	$( "#oscam_vmsize" ).text( data.oscam.sysinfo.oscam_vmsize );
	$( "#oscam_rsssize" ).text( data.oscam.sysinfo.oscam_rsssize );
	$( "#cpu_load_0" ).text( data.oscam.sysinfo.cpu_load_0 );
	$( "#cpu_load_1" ).text( data.oscam.sysinfo.cpu_load_1 );
	$( "#cpu_load_2" ).text( data.oscam.sysinfo.cpu_load_2 );
	$( "#oscam_refresh" ).text( data.oscam.sysinfo.oscam_refresh );
	$( "#oscam_cpu_user" ).text( data.oscam.sysinfo.oscam_cpu_user );
	$( "#oscam_cpu_sys" ).text( data.oscam.sysinfo.oscam_cpu_sys );
	$( "#oscam_cpu_sum" ).text( data.oscam.sysinfo.oscam_cpu_sum );

	// user + ecm totals
	$( "#total_users" ).text( data.oscam.status.totals.total_users );
	$( "#total_active" ).text( data.oscam.status.totals.total_active );
	$( "#total_connected" ).text( data.oscam.status.totals.total_connected );
	$( "#total_online" ).text( data.oscam.status.totals.total_online );
	$( "#total_disabled" ).text( data.oscam.status.totals.total_disabled );
	$( "#total_expired" ).text( data.oscam.status.totals.total_expired );
	$( "#total_cwok" ).text( data.oscam.status.totals.total_cwok );
	$( "#rel_cwok" ).text( data.oscam.status.totals.rel_cwok );
	$( "#total_cwcache" ).text( data.oscam.status.totals.total_cwcache );
	$( "#rel_cwcache" ).text( data.oscam.status.totals.rel_cwcache );
	$( "#total_cwnok" ).text( data.oscam.status.totals.total_cwnok );
	$( "#rel_cwnok" ).text( data.oscam.status.totals.rel_cwnok );
	$( "#total_cwtout" ).text( data.oscam.status.totals.total_cwtout );
	$( "#rel_cwtout" ).text( data.oscam.status.totals.rel_cwtout );
	$( "#total_cwign" ).text( data.oscam.status.totals.total_cwign );
	$( "#rel_cwign" ).text( data.oscam.status.totals.rel_cwign );
	$( "#total_ecm_min" ).text( data.oscam.status.totals.total_ecm_min );
	$( "#total_cw" ).text( data.oscam.status.totals.total_cw );
	$( "#total_cwpos" ).text( data.oscam.status.totals.total_cwpos );
	$( "#rel_cwpos" ).text( data.oscam.status.totals.rel_cwpos );
	$( "#total_cwneg" ).text( data.oscam.status.totals.total_cwneg );
	$( "#rel_cwneg" ).text( data.oscam.status.totals.rel_cwneg );

	// cachex
	$( "#total_cachexpush" ).text( data.oscam.status.totals.total_cachexpush );
	$( "#total_cachexgot" ).text( data.oscam.status.totals.total_cachexgot );
	$( "#total_cachexhit" ).text( data.oscam.status.totals.total_cachexhit );
	$( "#rel_cachexhit" ).text( data.oscam.status.totals.rel_cachexhit );
	$( "#total_cachesize" ).text( data.oscam.status.totals.total_cachesize );

	// hide heartbeat
	setTimeout(function (){$( "input.pintervall" ).css("background-color",orgstyle);}, 300);
}

/*
 *  General fork into page refresh functions
 */
function updatePage(data){
	switch(page){
	case 'status': 	updateStatuspage(data); 	break;
	case 'user': 	updateUserpage(data); 		break;
	case 'reader': 	updateReaderpage(data); 	break;
	case 'livelog':	updateLogpage(data); 		break;
	default: 					break;
	}
}

/*
 * General Polling
 */
function waitForMsg(){
	$.ajax({
		type: "GET",
		url: jsonurl + parameters,
		dataType: "JSON",
		async: true,
		cache: false,
		success: function(data){
			updatePage(data);
			if(!stoppoll) {
				setTimeout("waitForMsg()", pollintervall);
			}
		},
		error: function(XMLHttpRequest, textStatus, errorThrown) {
			setTimeout("waitForMsg()", 15000);
		}
	});
}

/*
 * General: Set Poll Interval
 */
function setPollrefresh(){
	// Set pollintervall, if httprefresh set to 0 disable polling
	if (httprefresh) {
		pollintervall = parseInt(httprefresh) * 1000;
		if (pollintervall > 99000) pollintervall == 99000;
		if(!nostorage){
			if (sessionStorage.pollintervall) pollintervall = sessionStorage.pollintervall;
			else sessionStorage.pollintervall = pollintervall;
		}
	}
}

// static for paranoid Browsers
var nostorage = 0;

/*
 * General: Start Polling
 */
$(document).ready(function() {
	
	if(!localStorage){ 
		nostorage = 1;
		// remove whole filter block - makes no sense
		// without saving
		$('#regex').remove();
	}
	
	switch(page){
		case 'livelog':

			if(!nostorage){
				for(var i = 1; i < 6; i++) {
					var pattern = localStorage['regex' + i];
					var color = localStorage['color' + i];
					var fcolor = localStorage['fcolor' + i];
					$('#regex' + i).val(pattern?pattern:'');
					$('#color' + i).val(color?color:'');
					$('#fcolor' + i).val(fcolor?fcolor:'');
					$('#color' + i).colorPicker();
					$('#fcolor' + i).colorPicker();
					$('#whitelisted' + i).prop('checked', localStorage['whitelisted' + i] == '1'?true:false);
					$('#hidden' + i).prop('checked', localStorage['hidden' + i] == '1'?true:false);
				}
			}
			waitForMsg();

		break;
		default:
			if (page == 'status') $( "#chart" ).hide();
		
			// if httprefresh set to 0 hide pollselector
			setPollrefresh();
			if (httprefresh) {
				$(":text[name='pintervall']").val(pollintervall/1000);
				$("#poll").show();
				waitForMsg();
			} else {
				$("#nopoll").show();
			}
			
		break;
	}
});

/**
 * Really Simple Color Picker in jQuery
 *
 * Licensed under the MIT (MIT-LICENSE.txt) licenses.
 *
 * Copyright (c) 2008-2012
 * Lakshan Perera (www.laktek.com) & Daniel Lacy (daniellacy.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */(function(a){var b,c,d=0,e={control:a('<div class="colorPicker-picker">&nbsp;</div>'),palette:a('<div id="colorPicker_palette" class="colorPicker-palette" />'),swatch:a('<div class="colorPicker-swatch">&nbsp;</div>'),hexLabel:a('<label for="colorPicker_hex">Hex</label>'),hexField:a('<input type="text" id="colorPicker_hex" />')},f="transparent",g;a.fn.colorPicker=function(b){return this.each(function(){var c=a(this),g=a.extend({},a.fn.colorPicker.defaults,b),h=a.fn.colorPicker.toHex(c.val().length>0?c.val():g.pickerDefault),i=e.control.clone(),j=e.palette.clone().attr("id","colorPicker_palette-"+d),k=e.hexLabel.clone(),l=e.hexField.clone(),m=j[0].id,n,o;a.each(g.colors,function(b){n=e.swatch.clone(),g.colors[b]===f?(n.addClass(f).text("X"),a.fn.colorPicker.bindPalette(l,n,f)):(n.css("background-color","#"+this),a.fn.colorPicker.bindPalette(l,n)),n.appendTo(j)}),k.attr("for","colorPicker_hex-"+d),l.attr({id:"colorPicker_hex-"+d,value:h}),l.bind("keydown",function(b){if(b.keyCode===13){var d=a.fn.colorPicker.toHex(a(this).val());a.fn.colorPicker.changeColor(d?d:c.val())}b.keyCode===27&&a.fn.colorPicker.hidePalette()}),l.bind("keyup",function(b){var d=a.fn.colorPicker.toHex(a(b.target).val());a.fn.colorPicker.previewColor(d?d:c.val())}),a('<div class="colorPicker_hexWrap" />').append(k).appendTo(j),j.find(".colorPicker_hexWrap").append(l),g.showHexField===!1&&(l.hide(),k.hide()),a("body").append(j),j.hide(),i.css("background-color",h),i.bind("click",function(){c.is(":not(:disabled)")&&a.fn.colorPicker.togglePalette(a("#"+m),a(this))}),b&&b.onColorChange?i.data("onColorChange",b.onColorChange):i.data("onColorChange",function(){}),(o=c.data("text"))&&i.html(o),c.after(i),c.bind("change",function(){c.next(".colorPicker-picker").css("background-color",a.fn.colorPicker.toHex(a(this).val()))}),c.val(h);if(c[0].tagName.toLowerCase()==="input")try{c.attr("type","hidden")}catch(p){c.css("visibility","hidden").css("position","absolute")}else c.hide();d++})},a.extend(!0,a.fn.colorPicker,{toHex:function(a){if(a.match(/[0-9A-F]{6}|[0-9A-F]{3}$/i))return a.charAt(0)==="#"?a:"#"+a;if(!a.match(/^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/))return!1;var b=[parseInt(RegExp.$1,10),parseInt(RegExp.$2,10),parseInt(RegExp.$3,10)],c=function(a){if(a.length<2)for(var b=0,c=2-a.length;b<c;b++)a="0"+a;return a};if(b.length===3){var d=c(b[0].toString(16)),e=c(b[1].toString(16)),f=c(b[2].toString(16));return"#"+d+e+f}},checkMouse:function(d,e){var f=c,g=a(d.target).parents("#"+f.attr("id")).length;if(d.target===a(f)[0]||d.target===b[0]||g>0)return;a.fn.colorPicker.hidePalette()},hidePalette:function(){a(document).unbind("mousedown",a.fn.colorPicker.checkMouse),a(".colorPicker-palette").hide()},showPalette:function(c){var d=b.prev("input").val();c.css({top:b.offset().top+b.outerHeight(),left:b.offset().left}),a("#color_value").val(d),c.show(),a(document).bind("mousedown",a.fn.colorPicker.checkMouse)},togglePalette:function(d,e){e&&(b=e),c=d,c.is(":visible")?a.fn.colorPicker.hidePalette():a.fn.colorPicker.showPalette(d)},changeColor:function(c){b.css("background-color",c),b.prev("input").val(c).change(),a.fn.colorPicker.hidePalette(),b.data("onColorChange").call(b,a(b).prev("input").attr("id"),c)},previewColor:function(a){b.css("background-color",a)},bindPalette:function(c,d,e){e=e?e:a.fn.colorPicker.toHex(d.css("background-color")),d.bind({click:function(b){g=e,a.fn.colorPicker.changeColor(e)},mouseover:function(b){g=c.val(),a(this).css("border-color","#598FEF"),c.val(e),a.fn.colorPicker.previewColor(e)},mouseout:function(d){a(this).css("border-color","#000"),c.val(b.css("background-color")),c.val(g),a.fn.colorPicker.previewColor(g)}})}}),a.fn.colorPicker.defaults={pickerDefault:"FFFFFF",colors:["000000","993300","333300","000080","333399","333333","800000","FF6600","808000","008000","008080","0000FF","666699","808080","FF0000","FF9900","99CC00","339966","33CCCC","3366FF","800080","999999","FF00FF","FFCC00","FFFF00","00FF00","00FFFF","00CCFF","993366","C0C0C0","FF99CC","FFCC99","FFFF99","CCFFFF","99CCFF","FFFFFF"],addColors:[],showHexField:!0}})(jQuery);
