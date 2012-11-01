//globals variables
packetCount=0;
data = undefined;
intervalId=undefined;



//none stop query to retrieve data packet	
function startDisplayPackets(){
	intervalId=window.setInterval("launchRetrievePackets()",500);
	console.log(intervalId);
}

//to retreive only new data
function launchRetrievePackets(){
	if(sniff_run==1){
		retrievePackets(packetCount, -1);
	}
}

//retrieve data from the server
function retrievePackets(from, to) { 		
	$.ajax({
		  url: "/sniff?from="+from+"&to="+to+"",
		  dataType: "json",
		  success: function(data) {
			if(data!=0)//code d'erreur
			{
				for (var i=0;i<data.length;i++)
				{
					packetCount++;
					var html ="<tr class=\"success\"><td>"+data[i].num+"</td><td>"+data[i].src+"</td><td>"+data[i].size+"</td><td>"+data[i].protocol+"</td><td>"+data[i].port+"</td></tr>";
					$("#packets").append(html);

				}

			}
		  },
		  error:function(XMLHttpRequest, textStatus, errorThrows){
		  	//erreur ...
		  	//alert('pas ok');
		  }
		});
	}

//in order to start the sniffer
$('#startstop').click(function() {
	if(sniff_run==1)
	{
		sniff_run=0;
		$.ajax({
			  url: "/stop",
			  type: "get",
			  dataType: "json",
			  success: function(data) {
				console.log(intervalId);
				window.clearInterval(intervalId)
				$('#startstop').text("Lancer");
			},
			  error:function(XMLHttpRequest, textStatus, errorThrows){
				alert('erreur '+data);
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
				$('#startstop').text("Arrêter");
				startDisplayPackets()
			  },
			  error:function(XMLHttpRequest, textStatus, errorThrows){
				alert('erreur '+data);
			  }
			});
	}
});
