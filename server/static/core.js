var token;
var valid_peername = /^[\w-\.]{3,20}$/;
var valid_base64 = /^[\w\+\/=\- \*]+$/;
var forceReset = false;


$(function(){
	token = localStorage.getItem('token');
	notif = $('.notif');
	$('#maintainance').css('margin-top', -$('#maintainance').height()/2);
	if(token !== null) {
		toggleLoading();
		$('#auth-btn').prop('disabled', true);
		$('#auth-pass').prop('disabled', true);
		$.get('/ajax/auth?token='+token, function(){
			toggleLoading();
			loginSuccessful();
		}).fail(function(req, textStatus){
			console.error("[Auth]Error: ", req.statusText, textStatus);
			toggleLoading();
			$('#auth-btn').prop('disabled', false);
			$('#auth-pass').prop('disabled', false);
		});
	}
	$('#auth-btn').click(authenticate);
	$('#auth-form').submit(authenticate);
	function authenticate(e) {
		clearNotif();
		var password = $('#auth-pass').val();
		toggleLoading();
		$.getJSON('/ajax/auth?password='+password, function(data){
			console.info("password response");
			toggleLoading();
			token = data.token;
			if(data.forceReset) {
				forceReset = true;
			}
			localStorage.setItem('token', token);
			loginSuccessful();
		}).fail(function(req, textStatus){
			console.error("[Auth]Error: ", req.status, textStatus);
			toggleLoading();
			if(req.status == 403) {
				showNotif("Wrong password");
				$('#auth-pass').focus().addClass('error')
					.on("transitionend webkitTransitionEnd", function() {
							$(this).removeClass("error");
					});
				}
			else {
				showNotif("Please try again later");
			}
		});
		e.preventDefault();
	}
	$('#add_peer').click(function(){
		clearNotif();
		var name = $('#new_peer').val();
		var pubkey = $('#new_pubkey').val();
		if(!(name&&pubkey)){
			return showNotif("Please enter the peer name and public key");
		}
		if(valid_peername.test(name) !== true) {
			return showNotif("username must contain only alphanumeric characters, underscores '_', dashes '-' and dots '.'");
		}
		if(valid_base64.test(pubkey) !== true) {
			return showNotif("Please enter a valid public key");
		}
		toggleLoading();
		$.post('/ajax/add_peer?token='+token+'&name='+encodeURIComponent(name)+'&pubkey='+encodeURIComponent(pubkey), function(){
			toggleLoading();
			reloadUsers();
		}).fail(function(req, textStatus){
			console.error("[Add Peer]Error: ", req.statusText, textStatus);
			toggleLoading();
			if(req.status == 403) {
				showNotif("Login expired");
				returnToLogin();
			}
			else {
				showNotif("Please try again later");
			}
		});
	});
	$('table').on('click', '.remove-peer, .icon-remove-sign', function(e){
		clearNotif();
		var target = $(e.target);
		if (target.hasClass('icon-remove-sign')) {
			target = target.parent();
		}
		var peer = target.data('peer');
		console.info($(e.target));
		toggleLoading();
		$.post('/ajax/remove_peer?token='+token+'&peer='+peer, function() {
			toggleLoading();
			target.parent().parent().remove();
		}).fail(function(req, textStatus){
			console.error("[Remove Peer]Error: ", req.statusText, textStatus);
			toggleLoading();
			if(req.status == 403) {
				showNotif("Login expired");
				returnToLogin();
			}
			else {
				showNotif("Please try again later");
			}
		});
	});
});

var loginSuccessful = function() {
	reloadUsers(function(){
		$('#auth').css('display', 'none');
		$('#maintainance').css('visibility', 'visible');
		clearNotif();
	});

};

var returnToLogin = function() {
	$('#auth').css('visibility', 'visible');
	$('#maintainance').css('visibility', 'hidden');
};

var reloadUsers = function(cb) {
	$.getJSON('/ajax/list?token='+token, function(data) {
		if(!data) {
			return $('#auth_notif').text("Please try again later.");
		}
		var table_top = $('#table-top');
		data.forEach(function(item) {
			var user = decodeURIComponent(item.user);
			table_top.after('<tr><td><i class="icon-user"></i> '+ user +'</td><td>' +
				item.pubkey + '</td><td>' +
				item.ip + '</td><td>' +
				item.port + '</td><td>' +
				(Date.now() - item.lastPing < 60*1000 ? '<i class="icon-signal"></i>' : '<i class="icon-ban-circle"></i>') +
				'</td><td><button class="remove-peer" type="button" data-peer="'+ user +
				'"><i class="icon-remove-sign"></i></button></td></tr>'
			);
		});
		if(cb) {
			cb();
		}
	}).fail(function(req, textStatus){
			console.error("[List Peer]Error: ", req.statusText, textStatus);
			toggleLoading();
			if(req.status == 403) {
				showNotif("Login expired");
				returnToLogin();
			}
			else {
				showNotif("Please try again later");
			}
		});
};

var toggleLoading = function() {
	$('.icon-spinner').toggleClass('hidden');
};

var notif;
var showNotif = function(text) {
	notif.removeClass('hidden');
	notif.text(text);
};
var clearNotif = function() {
	notif.addClass('hidden');
};