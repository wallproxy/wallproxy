$(document).on('pageinit', '#save', function(){
$('#restart_btn').click(function() {
	$.mobile.loadingMessageTextVisible = true;
	$.mobile.showPageLoadingMsg('a', '正在重启...');
	$.get('/restart?'+Math.random(), function(data) {
		setTimeout(function() {
			$.mobile.hidePageLoadingMsg();
			$('.ui-dialog').dialog('close');
		}, 1000);
	});
});
});

function show_editor(div, title, file) {
	file = '/' + file;
	var elem = document.getElementById('editor_tmpl');
	div.html((elem.value || elem.innerHTML).replace('{{title}}', title));
	$('home_list').listview('refresh');
	var editor = {mode: 'text/x-ini', lineWrapping: true, lineNumbers: true}, crlf = '\r\n';
	if (file.match('\.py$')) {
		editor = {
			mode: {name:'python', version:2, singleLineStringErrors:true},
			lineWrapping: true,
			lineNumbers: true,
			indentUnit: 4,
			extraKeys: {Tab: 'indentMore'},
			matchBrackets: true
		};
		crlf = '\n';
	}
	editor = CodeMirror.fromTextArea(div.find('.code_box')[0], editor);
	div.on('pageshow', function(){
		$.get(file+'?'+Math.random(), function(data) {editor.setValue(data);});
	});
	div.find('.save_btn').click(function() {
		if (!confirm('保存配置并重启程序？')) return false;
		$.mobile.loadingMessageTextVisible = true;
		$.mobile.showPageLoadingMsg('a', '保存文件...');
		$.post(file, editor.getValue(crlf), function(data) {
			if (data != 'OK') {
				alert('保存失败: ' + data);
				$.mobile.hidePageLoadingMsg();
				return false;
			}
			$.mobile.showPageLoadingMsg('a', '重启程序...');
			$.get('/restart?'+Math.random(), function(data) {
				setTimeout(function() {
					$.mobile.hidePageLoadingMsg();
					history.back();
					return false;
				}, 500);
			});
		});
	});
}
$(document).on('pagecreate', '#proxy_ini', function(){
	show_editor($(this), '配置文件(ini)', 'proxy.ini');
});
$(document).on('pagecreate', '#config_py', function(){
	show_editor($(this), '配置文件(py)', 'config.py');
});
$(document).on('pagecreate', '#userlist_ini', function(){
	show_editor($(this), '自定义规则', 'userlist.ini');
});
