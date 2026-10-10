// Profile preset.
// Rule mode; TUN on; DNS override and IPv6 off.

function main(input) {
  var original = JSON.parse(JSON.stringify(input || {}));
  try {
    return cpUniversal(original);
  } catch (error) {
    // Keep available local routes.
    console.error('[Profile] Stopped: ' + error.message);
    original.mode = 'rule';
    original.ipv6 = false;
    var rejectedDns = ['https://1.1.1.1/dns-query#REJECT'];
    var resources = original['rule-providers'] || {};
    var classification = ['CN', 'Foreign', 'OpenAI', 'Gemini'].every(function (name) {
      return !!resources['CP-U-' + name];
    });
    var policy = {};
    var rules = [];
    if (classification) {
      cpFinanceDomains().forEach(function (domain) {
        policy['+.' + domain] = rejectedDns;
        rules.push('DOMAIN-SUFFIX,' + domain + ',DIRECT');
      });
      policy['rule-set:CP-U-OpenAI,CP-U-Gemini,CP-U-Foreign'] = rejectedDns;
      policy['rule-set:CP-U-CN'] = cpDomesticDns();
      rules.push('RULE-SET,CP-U-OpenAI,REJECT', 'RULE-SET,CP-U-Gemini,REJECT',
        'RULE-SET,CP-U-Foreign,REJECT', 'RULE-SET,CP-U-CN,DIRECT');
    }
    original.dns = cpDns(rejectedDns, policy, {});
    original.rules = rules.concat(['MATCH,REJECT']);
    return original;
  }
}

function cpUniversal(config) {
  var prefix = 'CP-U-';
  var proxy = prefix + 'Proxy';
  var automatic = prefix + 'Auto';
  var dnsGroup = prefix + 'DNS';
  var nodes = Array.isArray(config.proxies) ? config.proxies : [];
  var providers = Object.keys(config['proxy-providers'] || {});
  var nodeMap = Object.create(null);
  nodes.forEach(function (node) { nodeMap[node.name] = node; });
  var usable = nodes.filter(function (node) {
    return node.name && !/^(direct|reject|reject-drop|pass|compatible|dns)$/i.test(node.type || '');
  });
  var names = usable.map(function (node) { return node.name; });
  if (!names.length && !providers.length) throw new Error('No usable proxy nodes or providers.');

  var inheritedGroups = (config['proxy-groups'] || []).filter(function (group) {
    return group.name !== 'ChatGPT' && group.name !== 'Gemini' && group.name.indexOf(prefix) !== 0;
  }).map(function (group) {
    return Object.assign({}, group, { 'empty-fallback': 'REJECT' });
  });
  var groupMap = Object.create(null);
  inheritedGroups.forEach(function (group) { groupMap[group.name] = group; });
  var inheritedRules = config.rules || [];
  var regions = [
    ['HK', /\ud83c\udded\ud83c\uddf0|\u9999\u6e2f|\bHK\b|Hong[ _-]?Kong/i],
    ['TW', /\ud83c\uddf9\ud83c\uddfc|\u53f0\u6e7e|\u53f0\u7063|\bTW\b|Taiwan/i],
    ['SG', /\ud83c\uddf8\ud83c\uddec|\u65b0\u52a0\u5761|\u72ee\u57ce|\u7345\u57ce|\bSG\b|Singapore/i],
    ['JP', /\ud83c\uddef\ud83c\uddf5|\u65e5\u672c|\u4e1c\u4eac|\u6771\u4eac|\u5927\u962a|\bJP\b|Japan/i],
    ['US', /\ud83c\uddfa\ud83c\uddf8|\u7f8e\u56fd|\u7f8e\u570b|\bUS\b|USA|United[ _-]?States/i],
    ['DE', /\ud83c\udde9\ud83c\uddea|\u5fb7\u56fd|\u5fb7\u570b|\bDE\b|Germany/i],
    ['UK', /\ud83c\uddec\ud83c\udde7|\u82f1\u56fd|\u82f1\u570b|\bUK\b|\bGB\b|United[ _-]?Kingdom/i],
    ['KR', /\ud83c\uddf0\ud83c\uddf7|\u97e9\u56fd|\u97d3\u570b|\bKR\b|Korea/i],
    ['FR', /\ud83c\uddeb\ud83c\uddf7|\u6cd5\u56fd|\u6cd5\u570b|\bFR\b|France/i],
    ['CA', /\ud83c\udde8\ud83c\udde6|\u52a0\u62ff\u5927|\bCA\b|Canada/i],
    ['AU', /\ud83c\udde6\ud83c\uddfa|\u6fb3\u5927\u5229\u4e9a|\u6fb3\u5927\u5229\u4e9e|\u6fb3\u6d32|\bAU\b|Australia/i]
  ];
  var countryGroups = [];
  var countries = Object.create(null);
  regions.forEach(function (region) {
    var members = usable.filter(function (node) { return region[1].test(node.name); });
    if (members.length) {
      var name = prefix + region[0];
      countries[region[0]] = name;
      countryGroups.push(cpGroup(name, 'select', members.map(function (node) { return node.name; })));
    }
  });
  var managedNames = [automatic, proxy, dnsGroup, 'ChatGPT', 'Gemini'].concat(
    countryGroups.map(function (group) { return group.name; })
  );
  managedNames.forEach(function (name) {
    if (nodeMap[name]) throw new Error('A node name collides with a managed strategy group.');
  });
  var autoGroup = cpGroup(automatic, 'url-test', names, providers);
  autoGroup.url = 'https://www.gstatic.com/generate_204';
  autoGroup.interval = 600;
  autoGroup.timeout = 5000;
  autoGroup.tolerance = 80;
  autoGroup.lazy = true;
  var preferred = ['US', 'JP', 'SG', 'TW'].map(function (country) {
    return countries[country];
  }).filter(Boolean);
  config['proxy-groups'] = inheritedGroups.concat([
    autoGroup,
    cpGroup(proxy, 'select', [automatic].concat(countryGroups.map(function (group) {
      return group.name;
    })).concat(names)),
    cpGroup(dnsGroup, 'select', [proxy]),
    cpGroup('ChatGPT', 'select', preferred.concat([proxy])),
    cpGroup('Gemini', 'select', preferred.concat([proxy]))
  ]).concat(countryGroups);

  // Shared service domains.
  var finance = cpFinanceDomains();
  var source = 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/';
  var ruleProviders = Object.assign({}, config['rule-providers'] || {});
  Object.keys(ruleProviders).forEach(function (name) {
    if (name.indexOf(prefix) === 0) delete ruleProviders[name];
  });
  [['CN', 'cn'], ['Foreign', 'geolocation-!cn'], ['OpenAI', 'openai'], ['Gemini', 'google-gemini']]
    .forEach(function (entry) {
      ruleProviders[prefix + entry[0]] = {
        type: 'http', behavior: 'domain', format: 'mrs',
        url: source + entry[1] + '.mrs',
        path: './rules/' + prefix + entry[0] + '.mrs',
        'path-in-bundle': 'geo/geosite/' + entry[1] + '.mrs',
        interval: 86400, proxy: proxy
      };
    });
  config['rule-providers'] = ruleProviders;

  var overseas = [
    'https://1.1.1.1/dns-query#' + dnsGroup,
    'https://8.8.8.8/dns-query#' + dnsGroup
  ];
  var oldDns = config.dns || {};
  var nodePolicy = cpEntryPolicy(oldDns, nodes);
  var policy = {};
  finance.forEach(function (domain) { policy['+.' + domain] = overseas; });
  policy['rule-set:' + prefix + 'OpenAI,' + prefix + 'Gemini,' + prefix + 'Foreign'] = overseas;
  policy['rule-set:' + prefix + 'CN'] = cpDomesticDns();
  config.dns = cpDns(overseas, policy, nodePolicy);
  var existingEntryResolvers = oldDns['proxy-server-nameserver'] || [];
  var encryptedEntryResolvers = existingEntryResolvers.filter(function (server) {
    return typeof server === 'string' && /^(https|tls|quic):\/\//i.test(server);
  });
  if (encryptedEntryResolvers.length) {
    config.dns['proxy-server-nameserver'] = encryptedEntryResolvers.map(cpDirectEncryptedDns);
  }
  if (typeof oldDns.listen === 'string' && oldDns.listen) config.dns.listen = oldDns.listen;

  var rules = finance.map(function (domain) { return 'DOMAIN-SUFFIX,' + domain + ',DIRECT'; });
  var localDomains = ['lan', 'local', 'localdomain', 'home.arpa'];
  rules.push('DOMAIN,localhost,DIRECT');
  localDomains.forEach(function (domain) { rules.push('DOMAIN-SUFFIX,' + domain + ',DIRECT'); });
  rules.push('RULE-SET,' + prefix + 'OpenAI,ChatGPT', 'RULE-SET,' + prefix + 'Gemini,Gemini');
  var inheritedForeign = [];
  inheritedRules.forEach(function (rule) {
    if (typeof rule !== 'string') return;
    var parts = rule.split(',');
    if (parts.length !== 3 || !/^(DOMAIN|DOMAIN-SUFFIX)$/.test(parts[0])) return;
    var domain = parts[1].replace(/^\./, '');
    if (!domain || domain.indexOf('.') < 0 || /[*+\s]/.test(domain)) return;
    var target = parts[2];
    if (target.indexOf(prefix) === 0) return;
    if (target === 'REJECT' || target === 'REJECT-DROP') rules.push(rule);
    else if (target === 'ChatGPT' || target === 'Gemini' || cpSafeTarget(target, nodeMap, groupMap, [])) {
      rules.push(rule);
      inheritedForeign.push('+.' + domain);
    }
  });
  // Exact policies first.
  if (inheritedForeign.length) {
    var orderedPolicy = {};
    finance.forEach(function (domain) { orderedPolicy['+.' + domain] = overseas; });
    inheritedForeign.forEach(function (domain) { orderedPolicy[domain] = overseas; });
    orderedPolicy['rule-set:' + prefix + 'OpenAI,' + prefix + 'Gemini,' + prefix + 'Foreign'] = overseas;
    orderedPolicy['rule-set:' + prefix + 'CN'] = cpDomesticDns();
    config.dns['nameserver-policy'] = orderedPolicy;
  }
  rules.push('RULE-SET,' + prefix + 'Foreign,' + proxy, 'RULE-SET,' + prefix + 'CN,DIRECT');
  // Domains before IP rules.
  rules.push('DOMAIN-REGEX,.+,' + proxy);
  ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '169.254.0.0/16', '224.0.0.0/4'].forEach(function (cidr) {
    rules.push('IP-CIDR,' + cidr + ',DIRECT,no-resolve');
  });
  rules.push('MATCH,' + proxy);
  config.rules = Array.from(new Set(rules));
  config.mode = 'rule';
  config.ipv6 = false;
  config.profile = Object.assign({}, config.profile || {}, {
    'store-selected': true, 'store-fake-ip': true
  });
  config.tun = Object.assign({}, config.tun || {}, {
    enable: true, 'auto-route': true, 'auto-detect-interface': true,
    'strict-route': true, 'dns-hijack': ['any:53'], 'inet6-address': [],
    'route-address': [], 'route-address-set': [],
    'route-exclude-address': [], 'route-exclude-address-set': [],
    'inet4-route-address': [], 'inet6-route-address': [],
    'inet4-route-exclude-address': [], 'inet6-route-exclude-address': []
  });
  if (!config.tun.stack) config.tun.stack = 'mixed';
  if (nodes.some(function (node) { return node['skip-cert-verify'] === true; })) {
    console.warn('[Profile] Some source nodes skip certificate checks.');
  }
  console.log('[Profile] Applied.');
  return config;
}

function cpGroup(name, type, proxies, providers) {
  var group = {
    name: name, type: type, proxies: proxies,
    'empty-fallback': 'REJECT', 'exclude-type': 'Direct|Reject|RejectDrop|Pass|Compatible|Dns',
    'exclude-filter': '(?i)^(DIRECT|REJECT|REJECT-DROP|PASS|COMPATIBLE|GLOBAL)$'
  };
  if (providers && providers.length) group.use = providers;
  return group;
}

function cpDomesticDns() {
  return ['https://223.5.5.5/dns-query#DIRECT'];
}

function cpFinanceDomains() {
  return [
    'interactivebrokers.com', 'interactivebrokers.com.hk', 'ibkr.com', 'ibllc.com',
    'hsbc.com.hk', 'airstarbank.com', 'elebank.com', 'welab.bank',
    'bank.za.group', 'sc.com', 'citibank.com.hk'
  ];
}

function cpDns(overseas, policy, nodePolicy) {
  return {
    enable: true, listen: '127.0.0.1:1053', ipv6: false,
    'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
    'fake-ip-filter-mode': 'blacklist',
    'fake-ip-filter': ['localhost', '+.lan', '+.local', '+.localdomain', '+.home.arpa',
      'dns.msftncsi.com', 'time.windows.com', 'time.apple.com', '+.pool.ntp.org'],
    'use-hosts': true, 'use-system-hosts': false, 'respect-rules': false,
    'default-nameserver': cpDomesticDns(),
    'proxy-server-nameserver': cpDomesticDns(),
    'proxy-server-nameserver-policy': nodePolicy,
    'nameserver': overseas, 'nameserver-policy': policy,
    'direct-nameserver': [], 'fallback': []
  };
}

function cpEntryPolicy(dns, nodes) {
  var entries = Object.assign({}, dns['proxy-server-nameserver-policy'] || {});
  var hosts = nodes.map(function (node) { return node.server; }).filter(function (host) {
    return typeof host === 'string' && host.indexOf(':') < 0 && !/^\d+(\.\d+){3}$/.test(host);
  });
  Object.keys(dns['nameserver-policy'] || {}).forEach(function (pattern) {
    if (hosts.some(function (host) { return cpDomainPattern(pattern, host); })) {
      if (!Object.prototype.hasOwnProperty.call(entries, pattern)) entries[pattern] = dns['nameserver-policy'][pattern];
    }
  });
  var result = {};
  Object.keys(entries).forEach(function (pattern) {
    // Explicit domains only.
    if (/^(geosite|rule-set):/i.test(pattern)) throw new Error('Entry DNS needs explicit domain policies.');
    var list = Array.isArray(entries[pattern]) ? entries[pattern] : [entries[pattern]];
    result[pattern] = list.map(cpDirectEncryptedDns);
    if (!result[pattern].length) throw new Error('An entry DNS policy has no resolver.');
  });
  return result;
}

function cpDirectEncryptedDns(server) {
  if (typeof server !== 'string' || !/^(https|tls|quic):\/\//i.test(server) ||
      /skip-cert-verify(?:=true|(?=&|$))/i.test(server)) {
    throw new Error('Entry-specific DNS is unencrypted or disables certificate verification.');
  }
  var parts = server.split('#');
  var params = (parts[1] || '').split('&').filter(function (part) {
    return part && part.indexOf('=') >= 0;
  });
  return parts[0] + '#DIRECT' + (params.length ? '&' + params.join('&') : '');
}

function cpDomainPattern(pattern, host) {
  if (/^(geosite|rule-set):/i.test(pattern)) return false;
  var suffix = pattern.replace(/^\+\./, '').replace(/^\*\./, '').toLowerCase();
  host = host.toLowerCase();
  return host === suffix || host.endsWith('.' + suffix);
}

function cpSafeTarget(name, nodes, groups, visited) {
  if (/^(DIRECT|COMPATIBLE|PASS|GLOBAL)$/i.test(name) || visited.indexOf(name) >= 0) return false;
  if (nodes[name]) return !/^(direct|reject|reject-drop|pass|compatible|dns)$/i.test(nodes[name].type || '');
  var group = groups[name];
  if (!group || group['include-all'] || group['include-all-proxies'] ||
      group['include-all-providers'] || (group.use && group.use.length)) return false;
  var members = group.proxies || [];
  return members.length > 0 && members.every(function (member) {
    return member === 'REJECT' || member === 'REJECT-DROP' ||
      cpSafeTarget(member, nodes, groups, visited.concat([name]));
  });
}
