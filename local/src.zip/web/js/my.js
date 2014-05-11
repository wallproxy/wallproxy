(function(){
function set_alert_dlg(title, msg, callback) {
	if (confirm(msg)) callback();
	// $('#alert_dlg').on('pageshow', function(){
		// var div = $(this);
		// div.find('.dlg_title').html(title);
		// div.find('.dlg_msg').html(msg);
		// div.find('.dlg_ok').unbind('click').click(callback);
	// });
}
function save_file(file, content) {
	set_alert_dlg('保存', '保存配置？', function(){
		$.mobile.loadingMessageTextVisible = true;
		$.mobile.showPageLoadingMsg('a', '保存文件...');
		$.post(file, content, function(data) {
			if (data != 'OK') {
				alert('保存失败: ' + data);
			}
			$.mobile.hidePageLoadingMsg();
			// $('.ui-dialog').dialog('close');
		});
	});
}
function save_and_restart(file, content) {
	set_alert_dlg('保存&amp;应用', '保存配置并重启程序？', function(){
		$.mobile.loadingMessageTextVisible = true;
		$.mobile.showPageLoadingMsg('a', '保存文件...');
		$.post(file, content, function(data) {
			if (data != 'OK') {
				alert('保存失败: ' + data);
				$.mobile.hidePageLoadingMsg();
				// $('.ui-dialog').dialog('close');
				return;
			}
			$.mobile.showPageLoadingMsg('a', '重启程序...');
			$.get('/restart?'+Math.random(), function(data) {
				setTimeout(function(){
					$.mobile.hidePageLoadingMsg();
					// $('.ui-dialog').dialog('close');
					history.back();
				}, 500);
			});
		});
	});
}
var ini_option = {mode: 'text/x-ini', lineWrapping: true, lineNumbers: true};
var py_option = {
	mode: {name:'python', version:2, singleLineStringErrors:true},
	lineWrapping: true,
	lineNumbers: true,
	indentUnit: 4,
	extraKeys: {Tab: 'indentMore'},
	matchBrackets: true
};
function create_editor(div, title, file) {
	div.html($('#editor_tmpl').html().replace('{{title}}', title));
	$('home_list').listview('refresh');
	var option = file.match('\.py$') ? py_option : ini_option;
	return CodeMirror.fromTextArea(div.find('.code_box')[0], option);
}
function show_editor(div, title, file) {
	var editor = create_editor(div, title, file);
	div.on('pageshow', function(){
		$.get(file+'?'+Math.random(), function(data){editor.setValue(data);});
	});
	div.find('.apply_btn').click(function(){
		save_and_restart(file, editor.getValue(file.match('\.py$') ? '\n' : '\r\n'));
		// div.find('.alert_dlg').click();
	});
	return editor;
}
function files_editor(div, title, files, file, prefix) {
	var i = files.length;
	if (i == 0) {
		files.push(file);
	} else {
		while (--i >= 0) {
			if (files[i] == file) break;
		}
		if (i < 0) file = files[0];
	}
	var path = prefix + file;
	var editor = create_editor(div, title, path);
	div.on('pageshow', function(){
		$.get(path+'?'+Math.random(), function(data){editor.setValue(data);}).fail(
			function(e){if(e.status == 404)editor.setValue('');});
	});
	div.find('.save_btn').removeClass('nd').click(function(){
		save_file(path, editor.getValue('\r\n'));
		// div.find('.alert_dlg').click();
	});
	div.find('.apply_btn').click(function(){
		save_and_restart(path, editor.getValue('\r\n'));
		// div.find('.alert_dlg').click();
	});
	var select = div.find('.file_choice');
	select.parent().removeClass('nd');
	for (i = 0; i < files.length; i++) {
		select.append('<option value="' +files[i]+ '">' +files[i]+ '</option>');
	}
	select.val(file);
	select.change(function(){
		path = prefix + $(this).val();
		$.get(path+'?'+Math.random(), function(data){editor.setValue(data);}).fail(
			function(e){if(e.status == 404)editor.setValue('');});
	});
}
$(document).on('pagecreate', '#proxy_ini', function(){
	files_editor($(this), '配置文件(ini)', ['proxy.ini', 'user.ini'], 'user.ini', '/');
});
$(document).on('pagecreate', '#config_py', function(){
	show_editor($(this), '配置文件(py)', '/config.py');
});
$(document).on('pagecreate', '#userlist_ini', function(){
	files_editor($(this), '自定义规则', WP.ini, 'userlist.ini', '/ini/');
});
})();
