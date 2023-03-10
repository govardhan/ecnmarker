#!/usr/bin/ucrun

'use strict';

import { connect } from 'ubus';
import { cursor } from 'uci';

const id = 'ecnmarker';

// TODO: get state from map
let bpf_enabled = false;

let time_enable = 5000;
let time_disable = 60000;

let ecnmarker_state = [];

let ubus = connect();

const EcnmarkerUbusProcedures = {
	get_state: {
		call: function(req) {
			let interfaces = ecnmarker_state;
			return req.reply({ interfaces });
		}
	}
};

function stop_service()
{
	ubus.call('service', 'delete', { name: id });
}

function prepare_filter_cmd(iface, dir, del) {
	let cmd = [ 'tc', 'filter', del ? 'del' : 'add', 'dev', iface, dir, 'prio', 0x100, 'bpf', 'object-file', '/lib/ecnmarker/ecnmarker-bpf.o', 'sec', 'tc', 'verbose', 'direct-action' ];

	return cmd;
}

function attach_bpf(iface, dir) {
	ulog_info('attaching ecnmarker bpf program to %s (%s)\n', iface, dir);

	let cmd = [ 'tc', 'qdisc', 'replace', 'dev', iface, 'clsact' ];
	let ret = system(cmd);
	if (ret) {
		ulog_err('failed to setup clsact qdisc on interface %s: %d\n', iface, ret);
		return;
	}

	cmd = prepare_filter_cmd(iface, dir, false);
	ret = system(cmd);
	if (ret) {
		ulog_err('failed to setup tc filter on interface %s: %d\n', iface, ret);
		return;
	}

	push(ecnmarker_state, { 'iface': iface, 'dir': dir });
}

function toggle_ecnmarker_bpf() {
	let cmd = '';
	let msg = '';
	let timeout = 1000;

	if (bpf_enabled) {
		cmd = [ 'bpftool', 'map', 'update', 'name', 'ecnmarker_enabl', 'key', 0, 0, 0, 0, 'value', 0 ];
		timeout = time_disable;
		msg = sprintf('disabled ECN-CE marking for %d ms\n', timeout);
	} else {
		cmd = [ 'bpftool', 'map', 'update', 'name', 'ecnmarker_enabl', 'key', 0, 0, 0, 0, 'value', 1 ];
		timeout = time_enable;
		msg = sprintf('enabled ECN-CE marking for %d ms\n', timeout);
	}

	let ret = system(cmd);
	if (ret) {
		timeout = 1000;
	} else {
		bpf_enabled = !bpf_enabled;
		ulog_info(msg);
	}

	return timeout;
}

function cb_timeout(data) {
	return toggle_ecnmarker_bpf();
}

global.ulog = {
	channels: [ 'stdio', 'syslog' ],
	identity: id,
};

global.start = function() {
	ulog_info('starting\n');

	ubus.publish(id, EcnmarkerUbusProcedures);

	let uci = cursor();
	uci.load(id);

	time_enable = +uci.get(id, "main", "time_enable_ms") || time_enable;
	time_disable = +uci.get(id, "main", "time_disable_ms") || time_disable;

	uci.foreach(id, 'interface', (s) => {
		if (s.disabled != '1') {
			attach_bpf(s.interface, s.direction);
		}
	});

	if (length(ecnmarker_state) > 0) {
		uloop_timeout(cb_timeout, 1000, { private: 'data' });
	} else {
		stop_service();
	}

};

global.stop = function() {
	ulog_info('stopping\n');

	for (let s in ecnmarker_state) {
		let cmd = prepare_filter_cmd(s.iface, s.dir, true);
		let ret = system(cmd);
		if (ret) {
			ulog_err("failed to remove tc filter on interface %s (%s): %d\n", s.iface, s.dir, ret);
		}
	}
};
