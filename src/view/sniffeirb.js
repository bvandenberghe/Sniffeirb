//globals variables
timestampCount = 0;
data = undefined; // ?
intervalId = undefined; //the id of the time loop
ipv4list = []; //store the list of ipv4 @ip
paquets = []; //store all packets received


//none stop query to retrieve data packet	
function startDisplayPackets(){
	intervalId=window.setInterval("launchRetrievePackets()",500);
	console.log(intervalId);
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


//add an @ip into the left menu
function addIPv4(ipv4){
	//we check if the @ip is already into the list	
	for (var i=0, length = ipv4list.length ;i<length;i++){
		if(ipv4list[i]==ipv4){
			return 0;
		}
	}

	//we add the new @ip to the list		
	ipv4list.push(ipv4);
	var htmlMenu = "<li><a href=\"#\">"+ipv4list[i]+"</a></li>";
	console.log("htmlMenu : "+htmlMenu);
	$("#IPV4").append(htmlMenu);
	
}


//retrieve data from the server
function retrievePackets(from, to) { 		
	$.ajax({
		  url: "/sniff?from="+from+"&to="+to+"",
		  dataType: "json",
		  success: function(data) {
			if(data!=0)//code d'erreur
			{	
				for (var i=0, length = data.length ;i<length;i++)
				{				
					//on enregistre tous les paquets dans un tableau
					paquets.push(data[i]);
					//on enregistre les nouvelles adresse ip dans un tableau				
					addIPv4(data[i].src);	
					if(data[i].initTS>timestampCount)
						timestampCount=data[i].initTS;
					var pktDate = new Date();
					
					pktDate.setTime(data[i].initTS*1000);
					date=pktDate.getDate()+"/"+(pktDate.getMonth()+1)+"/"+pktDate.getFullYear()+" "+pktDate.getHours()+":"+pktDate.getMinutes()+":"+pktDate.getSeconds()+":"+pktDate.getMilliseconds();
					//TODO : on les affiche selon le filtre (pour le moment pas de filtre donc on affiche tout)
					var html ="<tr class=\"success\"><td>"+date+"</td><td>"+data[i].src+" <b>:"+data[i].sport+"</b></td><td>"+data[i].dst+" <b>:"+data[i].dport+"</b></td><td>"+data[i].proto+"</td><td>"+data[i].size+"</td></tr>";
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

//clean the screen
$('#effacer').click(function() {
	ipv4list = [];
	paquets = [];
	$("#packets").html('');
	$("#IPV4").html('');
});

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
