// One EventSource per stream URL shared by every tab, so open tabs do not use up the browser's 6 HTTP/1.1 connections.
"use strict";
var streams = {};

function subscribe(port, url) {
  var s = streams[url];
  if (!s) {
    s = streams[url] = { source: new EventSource(url), ports: [] };
    s.source.onmessage = function (msg) {
      s.ports.forEach(function (p) { p.postMessage(msg.data); });
    };
  }
  if (s.ports.indexOf(port) === -1) s.ports.push(port);
}

function unsubscribe(port, url) {
  var s = streams[url];
  if (!s) return;
  s.ports = s.ports.filter(function (p) { return p !== port; });
  if (!s.ports.length) {
    s.source.close();
    delete streams[url];
  }
}

self.onconnect = function (e) {
  var port = e.ports[0];
  port.onmessage = function (m) {
    if (m.data && m.data.sub) subscribe(port, m.data.sub);
    if (m.data && m.data.unsub) unsubscribe(port, m.data.unsub);
  };
  port.start();
};
