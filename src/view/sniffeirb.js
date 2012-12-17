
//globals variables
timestampCount = 0;
data = undefined; // ?
intervalId = undefined; //the id of the time loop
paquets = []; //store all packets received
refreshInterval=500 //ms
currentSelectedArchive=undefined
oTable=undefined;

function initVar(){
	timestampCount = 0;
	data = undefined; // ?
	paquets = []; //store all packets received
	currentSelectedArchive=undefined
}

//Create the filtertable
$(document).ready(function() {

	
	/* Add the events etc before DataTables hides a column */
	$("thead input").keyup( function () {
		/* Filter on the column (the index) of this element */
		oTable.fnFilter( this.value, oTable.oApi._fnVisibleToColumnIndex( 
			oTable.fnSettings(), $("thead input").index(this) ) );
	} );
	
	/*
	 * Support functions to provide a little bit of 'user friendlyness' to the textboxes
	 */
	$("thead input").each( function (i) {
		this.initVal = this.value;
	} );
	
	$("thead input").focus( function () {
		if ( this.className == "search_init" )
		{
			this.className = "";
			this.value = "";
		}
	} );
	
	$("thead input").blur( function (i) {
		if ( this.value == "" )
		{
			this.className = "search_init";
			this.value = this.initVal;
		}
	} );
	
	oTable = $('#packetTable').dataTable( {
		"sDom": 'RC<"clear">lfrtip',
		
		"oLanguage": {
			"sSearch": "Search all columns:"
		},
		"bSortCellsTop": true,

    "aaSorting": [ [0,'asc'], [1,'asc'], [2,'asc'], [3,'asc'], [4,'asc'] ], //enable sort on each column
    "bLengthChange": true,
    "sScrollY": "300px"
	} );


    //Onclick event				
    $('#packetTable tbody tr').live('click', function () {
    var nTds = $('td', this);
       
    $.ajax({
			type: "GET",
			url: "/getdata?src="+$(nTds[1]).text()+"&dst="+$(nTds[2]).text(),
			dataType: "json",
			success: function(data) {
				var finalDisplayedData="";
				for(i=0;i<data.length;i++)
				{
					finalDisplayedData+="Flux "+(i+1)+":<br />"+data[i].data+"<hr>"
				}
				$("#displayData").html("<div class=\"alert alert-info\"><small><strong>"+finalDisplayedData+"</strong> </small></div>");
			}
		});
    oTable.$('tr.row_selected').removeClass('row_selected');
    $(this).addClass('row_selected');
   } );
	$(".TableTools").css("float","right");
	$("#packetTable_length").css("float","right");
	$("#packetTable_length").css("padding-right","5%");
   
});



//none stop query to retrieve data packet	
function startDisplayPackets(){
	intervalId=window.setInterval("launchRetrievePackets()",refreshInterval);
}
function displayAllPacketsOnce()
{
	retrievePackets(0, -1);
}
//to retreive only new data
function launchRetrievePackets(){
	if(sniff_run==1){
		retrievePackets(timestampCount, -1);
	}
}


//retrieve data from the server
function retrievePackets(from, to) { 		
	$.ajax({
		  url: "/sniff?from="+from+"&to="+to+"",
		  dataType: "json",
		  success: function(data) {
			if(data!=0 && data!=null)//code d'error
			{
				for (var i=0, length = data.length ;i<length;i++)
				{				
					//on enregistre tous les paquets dans un tableau
					paquets.push(data[i]);
					if(data[i].initTS>timestampCount)
						timestampCount=data[i].initTS;
					var pktDate = new Date();
					pktDate.setTime(data[i].initTS*1000);
					date=pktDate.getDate()+"/"+(pktDate.getMonth()+1)+"/"+pktDate.getFullYear()+" "+pktDate.getHours()+":"+pktDate.getMinutes()+":"+pktDate.getSeconds()+":"+pktDate.getMilliseconds();
                    //add the new packet into the filtertable                    					
				    $("#packetTable").dataTable().fnAddData([
				        date,
                        data[i].src+":"+data[i].sport,
				        data[i].dst+":"+data[i].dport,
				        data[i].proto+" - "+data[i].media,
				        data[i].size])
				    }
			}
		  },
		  error:function(XMLHttpRequest, textStatus, errorThrows){
		  	//error ...
		  	//alert('pas ok');
		  }
		});
	}


//clean the screen
$('#effacer').click(function() {
	paquets = [];
  	oTable._fnClearTable();
  	oTable._fnReDraw();
});

//change refreshing frequancy
$('#parameters').click(function() {
	refreshInterval=$("#frequence").val();
	$("#modal_parametre").hide();
});

//load old session
$('#loadArchive').click(function() {
	console.log("currentSelectedArchive"+currentSelectedArchive);
	$.ajax({
		  url: "/loadArchive",
   		 data: "idArchive="+currentSelectedArchive,
		  dataType: "json",
		  success: function(data) {
		  	oTable._fnClearTable();
		  	oTable._fnReDraw();
			retrievePackets(0, -1);
			initVar();
		  },
		  error:function(XMLHttpRequest, textStatus, errorThrows){
			console.log("error while loading archive");
		  }
		});

	$("#modal_parametre").hide();
});


//load the mongoDB entries of sniffeirb, in order to manage them
function loadArchive(){
		$.ajax({
			  url: "/getArchive",
			  type: "get",
			  dataType: "json",
			  success: function(data) {
				//add a new div element for all archives in mongoDB
				for(i=0; i<data.length;i++){
					$("#idArchive").append("<div id="+data[i]+" class=selectDB><hr/>"+data[i]+' <span class="delete" id="deleteU'+data[i]+'">&nbsp</span></div>');
					//define behaviour for deleting an archive
					$('#deleteU'+data[i]).click(function(){
							archiveName=$(this).attr('id').split('U');
							//query to the server that calls the deleting function.
							$.ajax({
								url: "/deleteArchive",
								type: "get",
								data: "idArchive="+archiveName[1],
								dataType: "json",
								success: function(msg) {
									$("#"+archiveName[1]).remove();
								},
								  error:function(XMLHttpRequest, textStatus, errorThrows){
									alert('error delete archive :  '+textStatus + errorThrows);
									}
							 });
						});
					
					//on click event
					$("#"+data[i]).click(function(){
						for(j=0;j<data.length;j++){
							$("#"+data[j]).css({"color" : ""});
							$("#"+data[j]).css({"font-weight": "normal"});
						}
						$(this).css({"color": "#990000"});
						$(this).css({"font-weight": "bold"});
						currentSelectedArchive=$(this).attr('id');
					});
				}
			},
			  error:function(XMLHttpRequest, textStatus, errorThrows){
				alert('error archive ');
			  }
		});
}


//in order to start and stop the sniffer
$('#startstop').click(function() {
	if(sniff_run==1)
	{
		sniff_run=0;
		$.ajax({
			  url: "/stop",
			  type: "get",
			  dataType: "json",
			  success: function(data) {

				window.clearInterval(intervalId)
				$('#startstop').text("Launch");
			},
			  error:function(XMLHttpRequest, textStatus, errorThrows){
				alert('error '+data);
			  }
			});
		
	}
	else
	{
		sniff_run=1;
		$.ajax({
			  url: "/start",
			  type: "get",
			  dataType: "json",
			  success: function(data) {
				$('#startstop').text("Stop");
				startDisplayPackets()
			  },
			  error:function(XMLHttpRequest, textStatus, errorThrows){
				alert('error '+data);
			  }
			});
	}
});
