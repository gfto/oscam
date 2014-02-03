var oReloadTimer=null;var oCounterTimer=null;
function reloadDocument(){history.pushState('', document.title, window.location.pathname);window.location.reload();};
function cdpause(){clearTimeout(oReloadTimer);};
function addreader(){cdpause();document.getElementById("searchTable").style.display="none";document.getElementById("newreader").style.display="block";};
function adduser(){cdpause();document.getElementById("searchTable").style.display="none";document.getElementById("newuser").style.display="block";};
function runReloadCounter(){var oReloadContent=document.getElementById("ReloadContent");if(oReloadContent){if(counter<0){counter=counterfull;}counter--;}};
function initDoc(){if(oReloadTimer)window.clearInterval(oReloadTimer);oReloadTimer=window.setInterval("reloadDocument();",counterfull*1000);if(oCounterTimer)window.clearInterval(oCounterTimer);oCounterTimer=window.setInterval("runReloadCounter();",1000);};
function gotosite(Action){window.location.href=Action;}

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
	