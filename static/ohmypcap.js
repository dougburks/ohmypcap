        function escapeHtml(str) {
            if (str == null) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function sortEventTypes(types) {
            const order = { alert: 0, filealerts: 1 };
            return [...types].sort((a, b) => {
                const ai = order[a] ?? 99;
                const bi = order[b] ?? 99;
                if (ai !== bi) return ai - bi;
                return a.localeCompare(b);
            });
        }

        const CLASSIFICATION_STYLES = {
            threat: { bg: '#ff6b6b33', text: '#ff6b6b' },
            technique: { bg: '#ffa72633', text: '#ffa726' },
            informational: { bg: '#9e9e9e33', text: '#9e9e9e' }
        };
        const COLORS = {
            EVENT: {
                alert: '#ff6b6b',
                anomaly: '#ff9800',
                dns: '#66bb6a',
                filealerts: '#e91e63',
                fileinfo: '#9c27b0',
                flow: '#bc8cff',
                ftp: '#00bcd4',
                http: '#ffa726',
                stats: '#9e9e9e',
                tls: '#58a6ff',
                connection: '#8b949e',
            },
            SEVERITY: {
                1: '#ff6b6b',
                2: '#ffa726',
                3: '#ffca28',
                4: '#66bb6a',
                default: '#8b949e',
            },
            FILE_ALERT: {
                bg: '#e91e6322',
                text: '#ff8a8a',
            },
        };
        const CONFIG = {
            MAX_QUERY_LIMIT: 10000,
            MAX_TYPE_QUERY_LIMIT: 5000,
            MAX_POLLING_ATTEMPTS: 120,
            POLLING_INTERVAL_MS: 1000,
            TLS_ISSUER_MAX_LENGTH: 30,
            AGGREGATION_TOP_N: 10,
            SEARCH_DEBOUNCE_MS: 300,
            SANKEY_BOTTOM_MARGIN: 60,
        };
        function getClassificationStyle(c) {
            return CLASSIFICATION_STYLES[c] || CLASSIFICATION_STYLES.informational;
        }
        function getClassificationLabel(c) {
            return c.charAt(0).toUpperCase() + c.slice(1);
        }
        function classificationBadgeHtml(c) {
            const s = getClassificationStyle(c);
            const l = getClassificationLabel(c);
            return `<span class="badge" style="background:${s.bg};color:${s.text}">${escapeHtml(l)}</span>`;
        }

        function showTab(sectionId, el) {
            document.querySelectorAll('.section').forEach(s => s.classList.add('section-hidden'));
            document.getElementById(sectionId).classList.remove('section-hidden');
            document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('tab-active'));
            if (el) el.classList.add('tab-active');
            
            const eventType = sectionId.replace('section-', '');
            loadTabData(eventType, el);
        }
        
        let tabDataCache = {};
        
        async function loadTabData(eventType, activeCard) {
            const sectionId = `section-${eventType}`;
            const sectionEl = document.getElementById(sectionId);
            const qParam = currentSearch.length > 0 ? currentSearch.map(t => '&q=' + encodeURIComponent(t)).join('') : '';
            
            if (activeCard) {
                activeCard.classList.add('tab-active');
            } else {
                document.querySelectorAll('.stat-card').forEach(card => {
                    const onclick = card.getAttribute('onclick');
                    if (onclick && onclick.includes(eventType)) {
                        const match = onclick.match(/showTab\('section-([^']+)'\)/);
                        if (match && match[1] === eventType) {
                            card.classList.add('tab-active');
                        }
                    }
                });
            }
            
            if (eventType === 'all') {
                if (allEvents.length === 0) {
                    try {
                        const resp = await fetch(`/api/events?md5=${currentMd5}&limit=${CONFIG.MAX_TYPE_QUERY_LIMIT}${qParam}&t=${Date.now()}`);
                        allEvents = await resp.json();
                    } catch(e) {
                        console.error('Failed to load all events:', e);
                    }
                }
                if (sectionEl) buildAllEvents();
                if (sectionEl && advancedMode) buildAggregationsSectionAll();
                updateFilterBarVisibility();
                updateSankeyDiagram();
                return;
            }
            
            if (tabDataCache[eventType]) {
                sections[eventType] = tabDataCache[eventType];
                const filtered = getFilteredEvents(sectionId, tabDataCache[eventType], eventType);
                if (advancedMode && sectionEl) {
                    buildAggregationsSection(eventType, filtered);
                    buildSection(eventType, tabDataCache[eventType]);
                } else if (sectionEl) {
                    buildSection(eventType, tabDataCache[eventType]);
                }
                updateFilterBarVisibility();
                updateSankeyDiagram();
                return;
            }
            
            try {
                const resp = await fetch(`/api/events?md5=${currentMd5}&type=${eventType}&limit=${CONFIG.MAX_QUERY_LIMIT}${qParam}&t=${Date.now()}`);
                const events = await resp.json();
                tabDataCache[eventType] = events;
                
                sections[eventType] = events;
                const filtered = getFilteredEvents(sectionId, events, eventType);
                if (advancedMode) {
                    if (sectionEl) {
                        buildAggregationsSection(eventType, filtered);
                    }
                }
                if (sectionEl) buildSection(eventType, events);
                updateFilterBarVisibility();
                updateSankeyDiagram();
            } catch(e) {
                console.error('Failed to load tab data:', e);
                if (sectionEl) {
                    sectionEl.innerHTML = `<div class="section-header">${typeLabels[eventType] || eventType.toUpperCase()}</div><div class="loading">Error loading data</div>`;
                }
            }
        }
        
        function toggleRow(tr) {
            const detailRow = tr.nextElementSibling;
            if (detailRow && detailRow.classList.contains('detail-row')) {
                const wasHidden = !detailRow.classList.contains('visible');
                tr.classList.toggle('expanded-row');
                detailRow.classList.toggle('visible');
                
                if (wasHidden) {
                    const asciiDiv = detailRow.querySelector('[id^="ascii-"]');
                    if (asciiDiv) {
                        const id = asciiDiv.id;
                        const parts = id.replace('ascii-', '').split('-');
                        if (parts.length >= 4) {
                            const srcIp = parts[0];
                            const srcPort = parts[1];
                            const dstIp = parts[2];
                            const dstPort = parts[3];
                            const pre = asciiDiv.querySelector('.ascii-transcript');
                            if (pre && !pre.innerHTML) {
                                pre.innerHTML = '<div style="color:#8b949e;padding:10px 0;display:flex;align-items:center;gap:8px;"><span class="ascii-loading"></span>Loading ASCII transcript...</div>';
                                loadAsciiTranscript(srcIp, srcPort, dstIp, dstPort, pre);
                            }
                        }
                    }
                }
            }
        }
        
        async function loadAsciiTranscript(src, sport, dst, dport, pre) {
            const md5Param = currentMd5 ? '&md5=' + encodeURIComponent(currentMd5) : '';
            const url = `/api/ascii-stream?src=${encodeURIComponent(src)}&sport=${encodeURIComponent(sport)}&dst=${encodeURIComponent(dst)}&dport=${encodeURIComponent(dport)}${md5Param}`;
            try {
                const resp = await fetch(url);
                const text = await resp.text();
                
                // Try to parse as JSON (new format with direction)
                try {
                    const data = JSON.parse(text);
                    if (data.lines && data.lines.length > 0) {
                        let html = '';
                        let groupHtml = '';
                        let lastDirection = '';
                        for (const line of data.lines) {
                            const direction = line.direction;
                            const color = direction === 'src' ? '#ff6b6b' : '#58a6ff';
                            if (direction !== lastDirection && groupHtml) {
                                const bar = `<span style="display:inline-block;width:3px;background:${lastDirection === 'src' ? '#ff6b6b' : '#58a6ff'};margin-right:8px;flex-shrink:0;"></span>`;
                                html += `<div style="display:flex;align-items:stretch;">${bar}<div style="flex:1;">${groupHtml}</div></div>`;
                                groupHtml = '';
                            }
                            groupHtml += line.text.split('\n').map(t => `<div>${escapeHtml(t)}</div>`).join('');
                            lastDirection = direction;
                        }
                        if (groupHtml) {
                            const bar = `<span style="display:inline-block;width:3px;background:${lastDirection === 'src' ? '#ff6b6b' : '#58a6ff'};margin-right:8px;flex-shrink:0;"></span>`;
                            html += `<div style="display:flex;align-items:stretch;">${bar}<div style="flex:1;">${groupHtml}</div></div>`;
                        }
                        pre.innerHTML = html;
                        if (data.truncated) {
                            pre.innerHTML += '<div style="margin-top:10px;color:#8b949e;font-style:italic;">[Truncated - stream too large. Use Download PCAP to view full capture.]</div>';
                        }
                        return;
                    }
                } catch (jsonErr) {
                    // Not JSON or parse failed, continue to plain text
                }
                
                // Legacy plain text format (backward compatibility)
                pre.textContent = text || 'No payload data';
            } catch(err) {
                pre.textContent = 'Error loading transcript: ' + err.message;
            }
        }
        
        async function switchStreamView(view, src, sport, dst, dport, btn) {
            const wrapper = btn.closest('div[id^="ascii-"]');
            const asciiEl = wrapper.querySelector('.ascii-transcript');
            const hexdumpEl = wrapper.querySelector('.hexdump-content');
            const tabs = wrapper.querySelectorAll('.view-tab');
            
            tabs.forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            
            if (view === 'hexdump') {
                asciiEl.style.display = 'none';
                hexdumpEl.style.display = '';
                if (hexdumpEl.dataset.loaded !== 'true') {
                    hexdumpEl.innerHTML = '<div style="color:#8b949e;padding:10px 0;"><span class="ascii-loading"></span>Loading hexdump...</div>';
                    await loadHexdumpData(src, sport, dst, dport, hexdumpEl);
                }
            } else {
                hexdumpEl.style.display = 'none';
                asciiEl.style.display = '';
            }
        }
        
        async function loadHexdumpData(src, sport, dst, dport, container) {
            const md5Param = currentMd5 ? '&md5=' + encodeURIComponent(currentMd5) : '';
            const url = `/api/hexdump-stream?src=${encodeURIComponent(src)}&sport=${encodeURIComponent(sport)}&dst=${encodeURIComponent(dst)}&dport=${encodeURIComponent(dport)}${md5Param}`;
            
            try {
                const resp = await fetch(url);
                const data = await resp.json();
                
                if (data.packets && data.packets.length > 0) {
                    let html = '<div class="packet-controls"><button class="packet-control-btn" onclick="expandAllPackets(this.parentNode.parentNode)">Expand All</button><button class="packet-control-btn" onclick="collapseAllPackets(this.parentNode.parentNode)">Collapse All</button></div>';
                    
                    data.packets.forEach((pkt, i) => {
                        const isExpanded = false;
                        const arrow = isExpanded ? '▾' : '▸';
                        const dirParts = pkt.header.split(' > ');
                        const isSrc = dirParts.length >= 2 ? dirParts[0].includes(src) : pkt.header.indexOf(src) < pkt.header.indexOf(dst);
                        const dirClass = isSrc ? 'src-dir' : 'dst-dir';
                        html += `
                            <div class="packet-block ${dirClass}">
                                <div class="packet-header" onclick="togglePacket(this)">
                                    <span>${arrow}</span><span>${escapeHtml(pkt.header)}</span>
                                </div>
                                <div class="packet-content${isExpanded ? '' : ' hidden'}">
                                    <pre>${escapeHtml(pkt.lines.join('\n'))}</pre>
                                </div>
                            </div>
                        `;
                    });
                    
                    if (data.truncated) {
                        html += '<div style="margin-top:10px;color:#8b949e;font-style:italic;">[Truncated - stream too large. Use Download PCAP to view full capture.]</div>';
                    }
                    
                    container.innerHTML = html;
                    container.dataset.loaded = 'true';
                } else {
                    container.innerHTML = '<div style="color:#8b949e;">No packets found</div>';
                    container.dataset.loaded = 'true';
                }
            } catch(err) {
                container.innerHTML = 'Error loading hexdump: ' + escapeHtml(err.message);
            }
        }
        
        function togglePacket(headerEl) {
            const contentEl = headerEl.nextElementSibling;
            const arrowEl = headerEl.querySelector('span:first-child');
            const isHidden = contentEl.classList.contains('hidden');
            arrowEl.textContent = isHidden ? '▾' : '▸';
            contentEl.classList.toggle('hidden');
        }
        
        function expandAllPackets(container) {
            container.querySelectorAll('.packet-content').forEach(el => el.classList.remove('hidden'));
            container.querySelectorAll('.packet-header > span:first-child').forEach(el => el.textContent = '▾');
        }
        
        function collapseAllPackets(container) {
            container.querySelectorAll('.packet-content').forEach(el => el.classList.add('hidden'));
            container.querySelectorAll('.packet-header > span:first-child').forEach(el => el.textContent = '▸');
        }
        
        function htmlRow(label, innerHtml, className, style) {
            const cls = className ? ` class="${className}"` : '';
            const sty = style ? ` style="${style}"` : '';
            return `<span style="color: #8b949e;">${escapeHtml(label)}</span><span${cls}${sty}>${innerHtml}</span>`;
        }
        
        function htmlRowText(label, text, className, style) {
            return htmlRow(label, escapeHtml(String(text || '')), className, style);
        }
        
        function htmlSection(title, color) {
            return `<span style="color: #8b949e; margin-top: 10px; grid-column: 1 / -1; border-bottom: 1px solid #30363d; padding-bottom: 5px; color: ${color};">${escapeHtml(title)}</span>`;
        }
        
        function formatEvent(e) {
            const ts = (e.timestamp || '').slice(0, 19);
            let html = `<div style="display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 8px; font-size: 0.85rem; min-width: 0;">`;
            html += htmlRowText('Timestamp', ts);
            html += htmlRow('Event Type', `<span class="badge badge-info">${escapeHtml(e.event_type || '')}</span>`);
            html += htmlRowText('Protocol', e.proto || '');
            html += htmlRowText('Flow ID', e.flow_id || '');
            html += htmlRowText('PCAP Count', e.pcap_cnt || '');
            
            html += htmlSection('Connection', COLORS.EVENT.connection);
            html += htmlRowText('Source IP', e.src_ip || '', 'mono');
            html += htmlRowText('Source Port', e.src_port || '', 'mono');
            html += htmlRowText('Dest IP', e.dest_ip || '', 'mono');
            html += htmlRowText('Dest Port', e.dest_port || '', 'mono');
            
            if (e.event_type === 'alert') {
                html += htmlSection('Alert Details', COLORS.EVENT.alert);
                html += htmlRowText('Signature', e.alert?.signature);
                html += htmlRow('Category', `<span class="badge badge-danger">${escapeHtml(e.alert?.category || '')}</span>`);
                html += htmlRowText('Severity', e.alert?.severity);
                html += htmlRowText('Action', e.alert?.action);
                html += htmlRowText('GID', e.alert?.gid);
                html += htmlRowText('SID', e.alert?.signature_id);
                html += htmlRow('Rule', escapeHtml(e.alert?.rule || ''), 'mono', 'white-space: pre-wrap; overflow-wrap: break-word; min-width: 0;');
            }
            
            if (e.event_type === 'dns') {
                html += htmlSection('DNS Details', COLORS.EVENT.dns);
                html += htmlRowText('Type', e.dns?.type);
                html += htmlRowText('Query Name', e.dns?.rrname, 'mono');
                html += htmlRowText('Query Type', e.dns?.rrtype);
                if (e.dns?.answers) {
                    html += htmlRowText('Answers', e.dns.answers.map(a => a.rdata).join(', '), 'mono');
                }
            }
            
            if (e.event_type === 'http') {
                html += htmlSection('HTTP Details', COLORS.EVENT.http);
                html += htmlRow('Method', `<span class="badge badge-info">${escapeHtml(e.http?.http_method || '')}</span>`);
                html += htmlRowText('Host', e.http?.hostname, 'mono');
                html += htmlRowText('URL', e.http?.url, 'mono');
                html += htmlRowText('User Agent', e.http?.http_user_agent, '', 'word-break: break-all;');
                html += htmlRowText('Status', e.http?.status);
                html += htmlRowText('Content Type', e.http?.http_content_type);
            }
            
            if (e.event_type === 'tls') {
                html += htmlSection('TLS Details', COLORS.EVENT.tls);
                html += htmlRowText('SNI', e.tls?.sni, 'mono');
                html += htmlRow('Version', `<span class="badge badge-info">${escapeHtml(e.tls?.version || '')}</span>`);
                html += htmlRowText('Subject', e.tls?.subject, 'mono');
                html += htmlRowText('Issuer', e.tls?.issuerdn, 'mono');
                html += htmlRowText('Not Before', e.tls?.notbefore);
                html += htmlRowText('Not After', e.tls?.notafter);
                html += htmlRowText('Fingerprint', e.tls?.fingerprint, 'mono');
            }
            
            if (e.event_type === 'flow') {
                html += htmlSection('Flow Details', COLORS.EVENT.flow);
                html += htmlRowText('State', e.flow?.state);
                html += htmlRowText('Age', `${e.flow?.age || ''} seconds`);
                html += htmlRowText('Pkts to Server', (e.flow?.pkts_toserver || 0).toLocaleString());
                html += htmlRowText('Pkts to Client', (e.flow?.pkts_toclient || 0).toLocaleString());
                html += htmlRowText('Bytes to Server', (e.flow?.bytes_toserver || 0).toLocaleString());
                html += htmlRowText('Bytes to Client', (e.flow?.bytes_toclient || 0).toLocaleString());
                html += htmlRowText('Alerted', e.flow?.alerted ? 'Yes' : 'No');
            }
            
            if (e.event_type === 'ftp') {
                html += htmlSection('FTP Details', COLORS.EVENT.ftp);
                html += htmlRowText('Command', e.ftp?.command);
                html += htmlRowText('Reply', e.ftp?.reply);
                html += htmlRowText('Data Channel', e.ftp?.data_channel?.active ? 'Active' : 'Passive');
            }
            
            if (e.event_type === 'anomaly') {
                html += htmlSection('Anomaly Details', COLORS.EVENT.anomaly);
                html += htmlRowText('Type', e.anomaly?.type);
                html += htmlRowText('Message', e.anomaly?.message);
            }
            
            if (e.event_type === 'filealerts') {
                const fa = e.filealerts || {};
                const classification = fa.classification || 'informational';
                html += htmlRow('Classification', classificationBadgeHtml(classification));
                html += htmlRow('Rule', `<span class="badge" style="background:${COLORS.FILE_ALERT.bg};color:${COLORS.FILE_ALERT.text}">${escapeHtml(fa.rule_name || '')}</span>`);
                html += htmlRowText('SHA256', fa.sha256, 'mono');
                html += htmlRowText('Tags', (fa.tags || []).join(', '));
                if (fa.meta && Object.keys(fa.meta).length > 0) {
                    const metaEntries = Object.entries(fa.meta).map(([k, v]) => `${k}: ${v}`).join(', ');
                    html += htmlRowText('Metadata', metaEntries);
                }
            }

            if (e.event_type === 'fileinfo') {
                html += htmlSection('File Info', COLORS.EVENT.fileinfo);
                html += htmlRowText('Filename', e.fileinfo?.filename, 'mono');
                html += htmlRowText('Magic', e.fileinfo?.magic);
                html += htmlRowText('MD5', e.fileinfo?.md5, 'mono');
                html += htmlRowText('SHA1', e.fileinfo?.sha1, 'mono');
                html += htmlRowText('SHA256', e.fileinfo?.sha256, 'mono');
                html += htmlRowText('Size', `${(e.fileinfo?.size || 0).toLocaleString()} bytes`);
                
                const fileSha = e.fileinfo?.sha256 || '';
                const matches = allEvents.filter(ev => ev.event_type === 'filealerts' && ev.filealerts?.sha256 === fileSha);
                html += htmlSection('File Alerts', COLORS.EVENT.filealerts);
                if (matches.length > 0) {
                    matches.forEach(m => {
                        html += htmlRow('Rule', `<span class="badge" style="background:${COLORS.FILE_ALERT.bg};color:${COLORS.FILE_ALERT.text}">${escapeHtml(m.filealerts?.rule_name || '')}</span>`);
                        if (m.filealerts?.tags && m.filealerts.tags.length) {
                            html += htmlRowText('Tags', m.filealerts.tags.join(', '));
                        }
                    });
                } else {
                    html += `<span style="color: #484f58; grid-column: 1 / -1;">No YARA matches</span>`;
                }
            }
            
            if (e.event_type === 'stats') {
                html += htmlSection('Stats Details', COLORS.EVENT.stats);
                if (e.stats?.capture) {
                    html += htmlRowText('Kernel Packets', (e.stats.capture.kernel_packets || 0).toLocaleString());
                    html += htmlRowText('Kernel Drops', (e.stats.capture.kernel_drops || 0).toLocaleString());
                }
                if (e.stats?.detect) {
                    html += htmlRowText('Alerts', (e.stats.detect.alert || 0).toLocaleString());
                }
            }
            
            html += `</div>`;
            
            if (e.src_ip && e.src_port && e.dest_ip && e.dest_port) {
                html += `<div id="ascii-${e.src_ip}-${e.src_port}-${e.dest_ip}-${e.dest_port}" style="margin-top: 15px;"><div style="color: #8b949e; font-size: 0.85rem; border-bottom: 1px solid #30363d; padding-bottom: 5px; margin-bottom: 5px;">Payload</div><div style="display: flex; justify-content: flex-start; align-items: center; margin-bottom: 10px;"><div class="view-tabs"><button class="view-tab active" onclick="switchStreamView('ascii','${e.src_ip}',${e.src_port},'${e.dest_ip}',${e.dest_port},this)">ASCII Transcript</button><button class="view-tab" onclick="switchStreamView('hexdump','${e.src_ip}',${e.src_port},'${e.dest_ip}',${e.dest_port},this)">Hexdump</button></div><button class="stream-btn" onclick="downloadPcap('${e.src_ip}','${e.src_port}','${e.dest_ip}','${e.dest_port}')" style="margin-left: 12px;">Download PCAP</button></div><div class="stream-view-container" style="background: #0d1117; padding: 15px; border-radius: 8px; font-size: 0.8rem; margin: 0;"><div class="ascii-transcript" style="white-space: pre-wrap; overflow-wrap: break-word;"></div><div class="hexdump-content" style="display: none;"></div></div></div>`;
            }
            
            return html;
        }
        
        function downloadPcap(src, sport, dst, dport) {
            const md5Param = currentMd5 ? '&md5=' + encodeURIComponent(currentMd5) : '';
            const url = `/api/download-stream?src=${encodeURIComponent(src)}&sport=${encodeURIComponent(sport)}&dst=${encodeURIComponent(dst)}&dport=${encodeURIComponent(dport)}${md5Param}`;
            const a = document.createElement('a');
            a.href = url;
            a.download = `stream_${src}_${sport}_to_${dst}_${dport}.pcap`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
        
        
        function sortTable(table, colIndex, th) {
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr')).filter(r => !r.classList.contains('detail-row'));
            const asc = !th.classList.contains('sort-asc');
            
            table.querySelectorAll('th').forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
                const arrow = h.querySelector('.sort-arrow');
                if (arrow) arrow.textContent = '';
            });
            
            th.classList.add(asc ? 'sort-asc' : 'sort-desc');
            let arrow = th.querySelector('.sort-arrow');
            if (!arrow) {
                arrow = document.createElement('span');
                arrow.className = 'sort-arrow';
                th.appendChild(arrow);
            }
            arrow.textContent = asc ? '▲' : '▼';
            
            rows.sort((a, b) => {
                let aVal = a.children[colIndex]?.textContent?.trim() || '';
                let bVal = b.children[colIndex]?.textContent?.trim() || '';
                
                if (!isNaN(aVal) && !isNaN(bVal) && aVal !== '' && bVal !== '') {
                    return asc ? parseFloat(aVal) - parseFloat(bVal) : parseFloat(bVal) - parseFloat(aVal);
                }
                return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            });
            
            const fragment = document.createDocumentFragment();
            rows.forEach(row => {
                fragment.appendChild(row);
                const detailRow = row.nextElementSibling;
                if (detailRow && detailRow.classList.contains('detail-row')) {
                    fragment.appendChild(detailRow);
                }
            });
            tbody.appendChild(fragment);
        }
        
        document.addEventListener('click', function(e) {
            if (e.target.tagName === 'TH') {
                const th = e.target;
                // Skip if cursor is default (non-sortable table)
                if (window.getComputedStyle(th).cursor === 'default') return;
                const table = th.closest('table');
                const thead = th.closest('thead');
                const index = Array.from(thead.querySelectorAll('th')).indexOf(th);
                sortTable(table, index, th);
            }
        });
        
        function renderTable(containerId, headers, rows) {
            let html = '<div class="section-content"><table><thead><tr>';
            headers.forEach(h => html += `<th>${h}</th>`);
            html += '</tr></thead><tbody>';
            rows.forEach(r => html += r);
            html += '</tbody></table></div>';
            document.getElementById(containerId).innerHTML = html;
        }
        
        function closeModal() {
            document.getElementById('streamModal').classList.remove('active');
        }
        
        function showLoading(message) {
            document.getElementById('loadingText').textContent = message || 'Loading...';
            document.getElementById('loadingModal').classList.add('active');
        }
        
        function hideLoading() {
            document.getElementById('loadingModal').classList.remove('active');
        }

        function clearAnalysisContainers() {
            document.getElementById('statsGrid').innerHTML = '';
            document.getElementById('sankeyPanel').style.display = 'none';
            document.getElementById('sankeyPanel').innerHTML = '';
            document.getElementById('aggregations').innerHTML = '';
            document.getElementById('sections').innerHTML = '';
            document.getElementById('filterBarContainer').innerHTML = '';
            document.getElementById('filterBarContainer').style.display = 'none';
            document.querySelectorAll('.file-info-card').forEach(c => c.remove());
            document.querySelectorAll('.file-alerts-grid').forEach(g => g.remove());
        }

        function showWelcomeUI() {
            document.getElementById('mainHeader').style.display = 'none';
            document.getElementById('dataPanel').style.display = 'none';
            document.getElementById('searchBarContainer').style.display = 'none';
            document.getElementById('inputBoxes').style.display = 'block';
        }

        function showAnalysisUI() {
            document.getElementById('inputBoxes').style.display = 'none';
            document.getElementById('mainHeader').style.display = 'block';
            document.getElementById('dataPanel').style.display = '';
            document.getElementById('searchBarContainer').style.display = 'block';
        }
        
        async function showWelcome() {
            document.title = 'OhMyPCAP - Welcome';
            if (window.location.search.includes('file=') || window.location.search.includes('pcap=')) {
                history.replaceState({}, '', window.location.pathname);
            }
            clearAnalysisContainers();
            showWelcomeUI();
            
            // Load previous analyses
            let previousHtml = '';
            try {
                const resp = await fetch('/api/analyses');
                const analyses = await resp.json();
                if (analyses.length > 0) {
                    previousHtml = analyses.map(a => 
                        `<div style="display: flex; align-items: center; padding: 8px 0; border-bottom: 1px solid #30363d;">
                            <a href="?file=${a.md5}" onclick="event.preventDefault(); loadAnalysis('${a.md5}');" style="color: #58a6ff; text-decoration: none; flex: 1;">📁 ${a.name}</a>
                            <button onclick="openReanalyzeModal('${a.md5}', '${a.name}')" style="background: #30363d; border: none; color: #58a6ff; cursor: pointer; font-size: 1rem; padding: 4px 10px; border-radius: 6px; margin-right: 4px;" title="Re-analyze">🔄</button>
                            <button onclick="openDeleteAnalysis('${a.md5}', '${a.name}')" style="background: #30363d; border: none; color: #ff6b6b; cursor: pointer; font-size: 1rem; padding: 4px 10px; border-radius: 6px;" title="Delete">🗑️</button>
                        </div>`
                    ).join('');
                } else {
                    previousHtml = '<span style="color: #484f58;">No previous PCAPs available</span>';
                }
            } catch(err) {
                console.error('Failed to load analyses:', err);
                previousHtml = '<span style="color: #484f58;">Error loading analyses</span>';
            }
            
            document.getElementById('inputBoxes').innerHTML = `
                <div style="max-width: 900px; margin: 0 auto;">
                    <div style="display: flex; justify-content: center; margin-bottom: 20px;">
                        <div style="background: #161b22; padding: 25px 40px; border-radius: 8px; border: 1px solid #30363d; text-align: center; flex: 1;">
                            <div style="font-size: 3rem; margin-bottom: 15px;">🔍</div>
                            <h2 style="color: #f0f6fc; font-size: 1.5rem; margin-bottom: 10px;">Welcome to OhMyPCAP</h2>
                            <p style="color: #8b949e; font-size: 0.95rem;">
                                Analyze files from the web or your local collection. View alerts and then slice and dice your network metadata!
                            </p>
                        </div>
                    </div>
                    <div style="display: flex; justify-content: center; margin-bottom: 20px;">
                        <div style="background: #161b22; padding: 25px 40px; border-radius: 8px; border: 1px solid #30363d; flex: 1;">
                            <p style="color: #8b949e; font-size: 0.95rem;">
                                💡 Maximum file size is 1000MB. Processing may take a minute or two depending on the size of the file.
                            </p>
                            <p style="color: #8b949e; font-size: 0.95rem; margin-top: 15px;">
                                💡 Upload PCAP files (.pcap, .pcapng, .cap, .trace) for full network traffic analysis, or any file for YARA-only scanning. ZIP files are also supported.
                            </p>
                            <p style="color: #8b949e; font-size: 0.95rem; margin-top: 15px;">
                                💡 If you don't already have a file in mind, just click the Go button below and it will automatically download a pcap from <a href="https://www.malware-traffic-analysis.net" target="_blank" rel="noopener noreferrer" style="color: #58a6ff; text-decoration: none;">malware-traffic-analysis.net</a>. There are lots of other fun pcap files to be found at that site!
                            </p>
                        </div>
                    </div>
                    <div style="display: flex; flex-direction: column; gap: 20px; margin-bottom: 20px;">
                        <div style="background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; width: 100%; box-sizing: border-box;">
                            <div style="color: #8b949e; font-size: 0.9rem; text-transform: uppercase; margin-bottom: 15px; font-weight: 600;">⬇️ Import file from URL or local filesystem</div>
                            <div style="display: flex; gap: 8px; margin-bottom: 15px;">
                                <input type="text" id="pcapUrl" value="https://www.malware-traffic-analysis.net/2026/02/03/2026-02-03-GuLoader-for-AgentTesla-style-infection-with-FTP-data-exfil.pcap.zip" onfocus="this.value=''" onkeydown="if(event.key==='Enter')loadFromUrl()" style="background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; padding: 8px 12px; border-radius: 4px; font-size: 0.95rem; flex: 1;">
                                <button onclick="loadFromUrl()" style="background: #58a6ff; color: #0d1117; padding: 8px 20px; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 0.95rem; border: none;">Go</button>
                            </div>
                            <div style="text-align: center; color: #8b949e; font-size: 0.9rem; font-weight: 600; text-transform: uppercase; margin-bottom: 15px;">— OR —</div>
                            <input type="file" id="pcapUpload" onchange="uploadPcap()" style="display: none;">
                            <div id="dropZone" style="background: #0d1117; color: #58a6ff; padding: 20px; border-radius: 4px; cursor: pointer; font-size: 0.95rem; border: 2px dashed #30363d; text-align: center; transition: border-color 0.2s, background 0.2s;"
                                 ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" ondrop="handleDrop(event)"
                                 onclick="document.getElementById('pcapUpload').click()">
                                <div style="font-size: 1.5rem; margin-bottom: 8px;">📂</div>
                                <div>Choose file or drag and drop here</div>
                            </div>
                        </div>
                    </div>
                    <div style="background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d;">
                        <div style="color: #8b949e; font-size: 0.9rem; text-transform: uppercase; margin-bottom: 15px; font-weight: 600;">📂 Previous Analyses</div>
                        <div id="previousAnalysesList">${previousHtml}</div>
                    </div>
                    <div style="background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; margin-top: 20px;">
                        <div style="color: #8b949e; font-size: 0.9rem; margin-bottom: 10px; text-align: center;">OhMyPCAP provides basic analysis. Need more advanced functionality?<br>Take a look at the <a href="https://securityonion.net" target="_blank" rel="noopener noreferrer" style="color: #58a6ff; text-decoration: none; font-weight: 600;">Security Onion</a> platform available in a free Community Edition!<br>If you need enterprise features, consider upgrading to <a href="https://securityonion.com/pro" target="_blank" rel="noopener noreferrer" style="color: #58a6ff; text-decoration: none; font-weight: 600;">Security Onion Pro</a>!</div>
                        <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                            <thead>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <th style="text-align: left; padding: 10px; color: #8b949e; font-size: 0.8rem; text-transform: none; cursor: default;">Feature</th>
                                    <th style="text-align: center; padding: 10px; color: #f0f6fc; font-size: 0.8rem; text-transform: none; cursor: default;">OhMyPCAP</th>
                                    <th style="text-align: center; padding: 10px; color: #f0f6fc; font-size: 0.8rem; text-transform: none; cursor: default;">Security Onion</th>
                                    <th style="text-align: center; padding: 10px; color: #f0f6fc; font-size: 0.8rem; text-transform: none; cursor: default;">Security Onion Pro</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Import PCAP File</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Review NIDS Alerts</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Slice and Dice Network Metadata</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Pivot to ASCII Transcript</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Download Carved PCAP</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Airgap / Offline Deployment</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Analyze Live Traffic</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Production Deployments</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Distributed Deployments</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Endpoint Visibility</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Log Management</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #30363d;">
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Case Management</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Guided Analysis</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Onion AI Assistant</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Open ID Connect (OIDC)</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Federal Information Processing Standards (FIPS)</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">STIG Compliance for the OS</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Connect API</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">External Notifications</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">Manager of Managers (MoM)</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                                <tr>
                                    <td style="padding: 8px 10px; color: #c9d1d9; font-size: 0.85rem;">MCP Server</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #484f58;">-</td>
                                    <td style="text-align: center; padding: 8px 10px; color: #66bb6a;">✅</td>
                                </tr>
                            </tbody>
                        </table>
                        <div style="margin-top: 15px; display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; font-size: 0.85rem;">
                            <a href="https://securityonion.net" target="_blank" rel="noopener noreferrer" style="color: #58a6ff; text-decoration: none;">Security Onion</a>
                            <span style="color: #30363d;">|</span>
                            <a href="http://securityonion.net/docs/about" target="_blank" rel="noopener noreferrer" style="color: #58a6ff; text-decoration: none;">Security Onion Documentation</a>
                            <span style="color: #30363d;">|</span>
                            <a href="https://securityonion.com/pro" target="_blank" rel="noopener noreferrer" style="color: #58a6ff; text-decoration: none;">Security Onion Pro</a>
                            <span style="color: #30363d;">|</span>
                            <a href="http://securityonion.net/docs/security-onion-pro" target="_blank" rel="noopener noreferrer" style="color: #58a6ff; text-decoration: none;">Security Onion Pro Documentation</a>
                        </div>
                    </div>
                </div>
            `;
            
            document.getElementById('pcapUrl').value = 'https://www.malware-traffic-analysis.net/2026/02/03/2026-02-03-GuLoader-for-AgentTesla-style-infection-with-FTP-data-exfil.pcap.zip';
        }
        
        document.getElementById('streamModal').addEventListener('click', function(e) {
            if (e.target === this) closeModal();
        });
        
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeModal();
        });
        
        // Single delegated listener for advanced toggle (prevents memory leak from repeated loadAnalysis calls)
        function toggleDiagram() {
            diagramMode = !diagramMode;
            updateSankeyDiagram();
        }
        
        function toggleAggregations() {
            advancedMode = !advancedMode;
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            if (!visibleSection) return;
            const eventType = visibleSection.id.replace('section-', '');
            if (advancedMode) {
                hiddenAggregations = new Set();
                if (eventType === 'all') {
                    buildAggregationsSectionAll();
                } else {
                    const events = tabDataCache[eventType] || sections[eventType] || [];
                    const filtered = getFilteredEvents(visibleSection.id, events, eventType);
                    buildAggregationsSection(eventType, filtered);
                }
            } else {
                const aggContainer = document.getElementById('aggregations');
                if (aggContainer) {
                    aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                }
            }
        }
        
        const typeLabels = {
            alert: 'Network Alerts',
            anomaly: 'Anomalies',
            dns: 'DNS Queries',
            filealerts: 'File Alerts',
            fileinfo: 'File Info',
            flow: 'Flows',
            ftp: 'FTP',
            http: 'HTTP',
            stats: 'Stats',
            tls: 'TLS'
        };
        
        function buildSankeyData(events) {
            const nodeMap = new Map();
            const linkMap = new Map();

            function getNodeId(name, column) {
                return column + ':' + name;
            }

            function addNode(name, column) {
                const id = getNodeId(name, column);
                if (!nodeMap.has(id)) {
                    nodeMap.set(id, { id: id, name: name, column: column });
                }
                return id;
            }

            function addLink(sourceId, targetId) {
                const key = sourceId + '->' + targetId;
                if (!linkMap.has(key)) {
                    linkMap.set(key, { source: sourceId, target: targetId, value: 0 });
                }
                linkMap.get(key).value += 1;
            }

            for (const e of events) {
                if (!e || e.event_type === 'stats') continue;
                const src = e.src_ip || '?';
                const dst = e.dest_ip || '?';
                const port = String(e.dest_port || '?');
                const srcId = addNode(src, 0);
                const dstId = addNode(dst, 1);
                const portId = addNode(port, 2);
                addLink(srcId, dstId);
                addLink(dstId, portId);
            }

            function capColumn(columnIndex, limit) {
                const columnNodes = Array.from(nodeMap.values()).filter(n => n.column === columnIndex);
                if (columnNodes.length <= limit) return;
                columnNodes.sort((a, b) => {
                    const av = Array.from(linkMap.values()).filter(l => l.source === a.id || l.target === a.id).reduce((s, l) => s + l.value, 0);
                    const bv = Array.from(linkMap.values()).filter(l => l.source === b.id || l.target === b.id).reduce((s, l) => s + l.value, 0);
                    return bv - av;
                });
                const keepIds = new Set(columnNodes.slice(0, limit).map(n => n.id));
                const otherId = addNode('Other', columnIndex);

                for (const node of columnNodes.slice(limit)) {
                    nodeMap.delete(node.id);
                }

                const newLinks = new Map();
                for (const [key, link] of linkMap) {
                    const s = link.source;
                    const t = link.target;
                    const sExists = nodeMap.has(s);
                    const tExists = nodeMap.has(t);
                    if (sExists && tExists) {
                        newLinks.set(key, link);
                    } else if (!sExists && tExists) {
                        const newKey = otherId + '->' + t;
                        const existing = newLinks.get(newKey);
                        if (existing) { existing.value += link.value; }
                        else { newLinks.set(newKey, { source: otherId, target: t, value: link.value }); }
                    } else if (sExists && !tExists) {
                        const newKey = s + '->' + otherId;
                        const existing = newLinks.get(newKey);
                        if (existing) { existing.value += link.value; }
                        else { newLinks.set(newKey, { source: s, target: otherId, value: link.value }); }
                    }
                }
                linkMap.clear();
                for (const [k, v] of newLinks) { linkMap.set(k, v); }
            }

            capColumn(0, 50);
            capColumn(1, 50);
            capColumn(2, 50);

            return { nodes: Array.from(nodeMap.values()), links: Array.from(linkMap.values()) };
        }

        function renderSankeySVG(data, container) {
            const width = container.clientWidth || 900;
            const nodesByCol = [[], [], []];
            for (const n of data.nodes) { nodesByCol[n.column].push(n); }
            const maxColNodes = Math.max(nodesByCol[0].length, nodesByCol[1].length, nodesByCol[2].length);
            const minNodeH = 8;
            const nodeGap = 4;
                    const height = Math.max(400, maxColNodes * (minNodeH + nodeGap) + CONFIG.SANKEY_BOTTOM_MARGIN);
            container.innerHTML = '';

            if (!data.nodes.length) return;

            const svg = d3.select(container).append('svg')
                .attr('class', 'sankey-svg')
                .attr('width', width)
                .attr('height', height)
                .attr('viewBox', [0, 0, width, height]);

            const nodeIndex = new Map();
            data.nodes.forEach((n, i) => nodeIndex.set(n.id, i));

            const graph = {
                nodes: data.nodes.map(n => ({ name: n.name, column: n.column })),
                links: data.links.map(l => ({
                    source: nodeIndex.get(l.source),
                    target: nodeIndex.get(l.target),
                    value: l.value
                }))
            };

            const sankey = d3.sankey()
                .nodeWidth(18)
                .nodePadding(nodeGap)
                .extent([[30, 35], [width - 30, height - 10]]);

            let { nodes, links } = sankey(graph);

            function ipToColor(ip) {
                let hash = 0;
                for (let i = 0; i < ip.length; i++) { hash = ((hash << 5) - hash) + ip.charCodeAt(i); }
                return 'hsl(' + (Math.abs(hash) % 360) + ', 70%, 60%)';
            }

            const linkGroup = svg.append('g');
            linkGroup.selectAll('path')
                .data(links)
                .join('path')
                .attr('class', 'sankey-link')
                .attr('d', d3.sankeyLinkHorizontal())
                .attr('stroke', d => ipToColor(d.source.name))
                .attr('stroke-width', d => Math.max(d.width, 1))
                .on('click', function(event, d) {
                    const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
                    if (!visibleSection) return;
                    applyFilters(visibleSection.id, [
                        {column: getColumnNameFromSankeyColumn(d.source.column), value: d.source.name},
                        {column: getColumnNameFromSankeyColumn(d.target.column), value: d.target.name}
                    ]);
                })
                .append('title')
                .text(d => d.source.name + ' \u2192 ' + d.target.name + ' (' + d.value + ')');

            const nodeGroup = svg.append('g')
                .selectAll('g')
                .data(nodes)
                .join('g')
                .attr('class', 'sankey-node')
                .attr('transform', d => 'translate(' + d.x0 + ',' + d.y0 + ')');

            nodeGroup.append('rect')
                .attr('height', d => d.y1 - d.y0)
                .attr('width', d => d.x1 - d.x0)
                .on('click', function(event, d) {
                    const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
                    if (!visibleSection) return;
                    applyFilters(visibleSection.id, [
                        {column: getColumnNameFromSankeyColumn(d.column), value: d.name}
                    ]);
                })
                .append('title')
                .text(d => d.name + ' (' + d.value + ')');

            nodeGroup.append('text')
                .attr('x', d => d.x0 < width / 2 ? (d.x1 - d.x0) + 5 : -5)
                .attr('y', d => (d.y1 - d.y0) / 2)
                .attr('dy', '0.35em')
                .attr('text-anchor', d => d.x0 < width / 2 ? 'start' : 'end')
                .style('opacity', d => (d.y1 - d.y0) >= minNodeH ? 1 : 0)
                .text(d => {
                    const label = d.name + ' (' + d.value + ')';
                    return label.length > 24 ? d.name.slice(0, 21) + '\u2026 (' + d.value + ')' : label;
                });

            const colLabels = ['Source IP', 'Dest IP', 'Dest Port'];
            const colCenters = [0, 1, 2].map(i => {
                const colNodes = nodes.filter(n => n.column === i);
                if (!colNodes.length) return width * (i + 0.5) / 3;
                return d3.mean(colNodes, n => (n.x0 + n.x1) / 2);
            });

            svg.append('g')
                .selectAll('text')
                .data(colLabels)
                .join('text')
                .attr('class', 'sankey-title')
                .attr('x', (d, i) => colCenters[i])
                .attr('y', 20)
                .attr('text-anchor', 'middle')
                .text(d => d);
        }

        function getSankeyEvents() {
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            if (!visibleSection) return [];
            const eventType = visibleSection.id.replace('section-', '');
            if (eventType === 'all') {
                return getFilteredEvents(visibleSection.id, allEvents, 'all');
            }
            const events = tabDataCache[eventType] || sections[eventType] || [];
            return getFilteredEvents(visibleSection.id, events, eventType);
        }

        function updateSankeyDiagram() {
            const sankeyPanel = document.getElementById('sankeyPanel');
            if (!sankeyPanel) return;
            sankeyPanel.innerHTML = '';

            if (!diagramMode) {
                sankeyPanel.innerHTML = '<div class="section-toggle-bar" onclick="toggleDiagram()">▸ Sankey Diagram</div>';
                return;
            }
            const events = getSankeyEvents();
            if (!events || events.length === 0) {
                sankeyPanel.innerHTML = '<div class="section-toggle-bar" onclick="toggleDiagram()">▾ Sankey Diagram</div>';
                return;
            }
            sankeyPanel.innerHTML = '<div class="section-toggle-bar" onclick="toggleDiagram()">▾ Sankey Diagram</div><div class="sankey-content"></div>';
            const svgContainer = sankeyPanel.querySelector('.sankey-content');
            const data = buildSankeyData(events);
            renderSankeySVG(data, svgContainer);
        }

        function getColumnsForType(eventType) {
            switch(eventType) {
                case 'alert':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Alert', 'Category', 'Severity'];
                case 'dns':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Query', 'Type'];
                case 'http':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Method', 'Host', 'URL', 'User-Agent', 'Status'];
                case 'tls':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'SNI / Host', 'Version', 'Subject', 'Issuer'];
                case 'flow':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Pkts →', 'Pkts ←', 'Bytes →', 'Bytes ←', 'State', 'Alerted'];
                case 'fileinfo':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Filename'];
                case 'filealerts':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Rule Name', 'Classification', 'Tags'];
                default:
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port'];
            }
        }
        
        function buildRowForEvent(e) {
            const ts = (e.timestamp || '').slice(0, 19);
            const etype = e.event_type || '';
            const proto = e.proto || '';
            const srcIp = e.src_ip || '';
            const srcPort = e.src_port || '';
            const dstIp = e.dest_ip || '';
            const dstPort = e.dest_port || '';
            const formatted = formatEvent(e);
            
            let row = '';
            let colSpan = 6;
            
            switch(etype) {
                case 'alert':
                    const sig = e.alert?.signature || 'N/A';
                    const cat = e.alert?.category || '';
                    const sev = e.alert?.severity || 0;
                    const sevColor = COLORS.SEVERITY[sev] || COLORS.SEVERITY.default;
                    colSpan = 9;
                    row = `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td><td>${escapeHtml(sig)}</td><td><span class="badge badge-danger">${escapeHtml(cat)}</span></td><td><span class="badge" style="background:${sevColor}33;color:${sevColor}">Sev ${sev}</span></td></tr>`;
                    break;
                case 'dns':
                    const rrname = e.dns?.rrname || '';
                    const rrtype = e.dns?.rrtype || '';
                    colSpan = 8;
                    row = `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td><td class="mono">${escapeHtml(rrname)}</td><td><span class="badge badge-info">${escapeHtml(rrtype)}</span></td></tr>`;
                    break;
                case 'http':
                    const method = e.http?.http_method || '';
                    const host = e.http?.hostname || '';
                    const url = e.http?.url || '';
                    const status = e.http?.status || '';
                    const ua = (e.http?.http_user_agent || '').slice(0, CONFIG.TLS_ISSUER_MAX_LENGTH);
                    const streamId = `${srcIp},${srcPort},${dstIp},${dstPort}`;
                    const statusBadge = status && parseInt(status) < 400 ? 'badge-success' : status && parseInt(status) < 500 ? 'badge-warning' : 'badge-danger';
                    colSpan = 11;
                    row = `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td><td><span class="badge badge-info">${escapeHtml(method)}</span></td><td class="mono">${escapeHtml(host)}</td><td class="mono">${escapeHtml(url)}</td><td>${escapeHtml(ua)}</td><td><span class="badge ${statusBadge}">${escapeHtml(String(status))}</span></td></tr>`;
                    break;
                case 'tls':
                    const sni = e.tls?.sni || '-';
                    const version = e.tls?.version || '-';
                    const subject = (e.tls?.subject || '-').slice(0, 40);
                    let issuer = e.tls?.issuerdn || '-';
                    if (issuer && issuer.includes('CN=')) issuer = issuer.split('CN=')[1].split(',')[0];
                    colSpan = 10;
                    row = `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td><td class="mono">${escapeHtml(sni)}</td><td><span class="badge badge-info">${escapeHtml(version)}</span></td><td class="mono">${escapeHtml(subject)}</td><td class="mono">${escapeHtml(issuer.slice(0, CONFIG.TLS_ISSUER_MAX_LENGTH))}</td></tr>`;
                    break;
                case 'flow':
                    const pktsTs = e.flow?.pkts_toserver || 0;
                    const pktsTc = e.flow?.pkts_toclient || 0;
                    const bytesTs = e.flow?.bytes_toserver || 0;
                    const bytesTc = e.flow?.bytes_toclient || 0;
                    const state = e.flow?.state || '';
                    const alerted = e.flow?.alerted || false;
                    const alertedBadge = alerted ? 'badge-danger' : 'badge-success';
                    const alertedText = alerted ? 'Yes' : 'No';
                    colSpan = 12;
                    row = `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td><td>${escapeHtml(String(pktsTs.toLocaleString()))}</td><td>${escapeHtml(String(pktsTc.toLocaleString()))}</td><td>${escapeHtml(String(bytesTs.toLocaleString()))}</td><td>${escapeHtml(String(bytesTc.toLocaleString()))}</td><td>${escapeHtml(state)}</td><td><span class="badge ${alertedBadge}">${escapeHtml(alertedText)}</span></td></tr>`;
                    break;
                case 'fileinfo':
                    const filename = e.fileinfo?.filename || '';
                    colSpan = 7;
                    row = `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td><td class="mono">${escapeHtml(filename)}</td></tr>`;
                    break;
                case 'filealerts':
                    const fa = e.filealerts || {};
                    const ruleName = fa.rule_name || 'N/A';
                    const tags = (fa.tags || []).join(', ');
                    const classification = fa.classification || 'informational';
                    colSpan = 9;
                    row = `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td><td style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"><span class="badge" style="background:${COLORS.FILE_ALERT.bg};color:${COLORS.FILE_ALERT.text}">${escapeHtml(ruleName)}</span></td><td>${classificationBadgeHtml(classification)}</td><td>${escapeHtml(tags)}</td></tr>`;
                    break;
                default:
                    colSpan = 6;
                    row = `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td></tr>`;
            }
            
            return row + `<tr class="detail-row"><td colspan="${colSpan}"><div class="detail-content">${formatted}</div></td></tr>`;
        }
        
        function buildFileInfoCard() {
            document.querySelectorAll('.file-info-card').forEach(c => c.remove());
            const fileinfoEvent = allEvents.find(e => e.event_type === 'fileinfo');
            if (!fileinfoEvent || !fileinfoEvent.fileinfo) return;
            
            const fi = fileinfoEvent.fileinfo;
            const card = document.createElement('div');
            card.className = 'file-info-card';
            card.innerHTML = `
                <h3>📄 File Info</h3>
                <div class="file-info-grid">
                    <span class="label">Filename</span><span class="value">${escapeHtml(fi.filename || '')}</span>
                    <span class="label">Size</span><span class="value">${escapeHtml(String((fi.size || 0).toLocaleString()))} bytes</span>
                    <span class="label">Magic</span><span class="value">${escapeHtml(fi.magic || '')}</span>
                    <span class="label">MD5</span><span class="value">${escapeHtml(fi.md5 || '')}</span>
                    <span class="label">SHA1</span><span class="value">${escapeHtml(fi.sha1 || '')}</span>
                    <span class="label">SHA256</span><span class="value">${escapeHtml(fi.sha256 || '')}</span>
                </div>
            `;
            
            const sections = document.getElementById('sections');
            if (sections) {
                sections.parentNode.insertBefore(card, sections);
            }
        }
        
        function buildFileAlertCards(events) {
            const container = document.getElementById('sections');
            if (!container) return;
            
            // Filter: show threat + technique by default
            const showInformational = false;
            const filteredEvents = events.filter(e => {
                const classification = (e.filealerts || {}).classification || 'informational';
                return showInformational || classification !== 'informational';
            });
            
            let html = '<div class="file-alerts-grid">';
            filteredEvents.forEach(e => {
                const fa = e.filealerts || {};
                const classification = fa.classification || 'informational';
                const tags = (fa.tags || []).join(', ');
                
                html += `
                    <div class="file-alert-card" onclick="showFileAlertDetail('${escapeHtml(fa.sha256 || '')}', '${escapeHtml(fa.rule_name || '')}')">
                        <div class="rule-name">${escapeHtml(fa.rule_name || 'Unknown')}</div>
                        <div class="card-footer">
                            ${classificationBadgeHtml(classification)}
                            <span class="tags">${escapeHtml(tags)}</span>
                        </div>
                    </div>
                `;
            });
            html += '</div>';
            container.innerHTML = html;
        }
        
        function formatFileAlertDetail(e) {
            const fa = e.filealerts || {};
            const classification = fa.confidence || 'informational';
            
            let html = '<div style="display: grid; grid-template-columns: 140px 1fr; gap: 8px 12px; font-size: 0.9rem;">';
            html += `<span style="color: #8b949e;">Classification</span><span>${classificationBadgeHtml(classification)}</span>`;
            html += `<span style="color: #8b949e;">Rule</span><span><span class="badge" style="background:${COLORS.FILE_ALERT.bg};color:${COLORS.FILE_ALERT.text}">${escapeHtml(fa.rule_name || '')}</span></span>`;
            html += `<span style="color: #8b949e;">SHA256</span><span class="mono">${escapeHtml(fa.sha256 || '')}</span>`;
            html += `<span style="color: #8b949e;">Tags</span><span>${escapeHtml((fa.tags || []).join(', '))}</span>`;
            if (fa.meta && Object.keys(fa.meta).length > 0) {
                const metaEntries = Object.entries(fa.meta).map(([k, v]) => `${k}: ${v}`).join(', ');
                html += `<span style="color: #8b949e;">Metadata</span><span>${escapeHtml(metaEntries)}</span>`;
            }
            html += '</div>';
            return html;
        }
        
        function showFileAlertDetail(sha256, ruleName) {
            // Find the matching event and show its detail panel
            const event = allEvents.find(e => 
                e.event_type === 'filealerts' && 
                (e.filealerts?.sha256 === sha256 || e.filealerts?.rule_name === ruleName)
            );
            if (!event) return;
            
            // Create a modal-like display for the detail
            const detailHtml = formatFileAlertDetail(event);
            const modal = document.createElement('div');
            modal.className = 'modal active';
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 600px;">
                    <div class="modal-header">
                        <h3>YARA Match Detail</h3>
                        <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
                    </div>
                    <div style="padding: 20px;">
                        ${detailHtml}
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
            
            // Close modal when clicking outside the content
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.remove();
                }
            });
        }
        
        function buildSection(eventType, events) {
            const sorted = [...events].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
            const columns = getColumnsForType(eventType);
            const sectionId = `section-${eventType}`;
            
            let filteredEvents = sorted;
            if (Object.keys(currentFilters).length > 0) {
                filteredEvents = sorted.filter(e => {
                    for (const [col, val] of Object.entries(currentFilters)) {
                        const colIndex = columns.indexOf(col);
                        const extracted = extractValue(e, col, colIndex);
                        if (extracted !== val) return false;
                    }
                    return true;
                });
            }
            
            const rows = filteredEvents.map(e => buildRowForEvent(e));
            
            const container = document.getElementById(sectionId);
            if (!container) return;
            
            let html = '<div class="section-content">';
            if (rows.length === 0 && Object.keys(currentFilters).length > 0) {
                html += EMPTY_FILTER_STATE_HTML;
            } else {
                html += '<table><thead><tr>';
                columns.forEach(h => html += `<th>${h}</th>`);
                html += '</tr></thead><tbody>';
                rows.forEach(r => html += r);
                html += '</tbody></table>';
            }
            html += '</div>';
            
            try {
                container.innerHTML = html;
            } catch(e) {
                console.error('Failed to render section:', e);
                container.innerHTML = '<div class="loading">Error rendering table</div>';
            }
        }
        
        function buildAggregationsSection(eventType, events) {
            const aggContainer = document.getElementById('aggregations');
            if (!aggContainer) return;
            
            if (!advancedMode) {
                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                return;
            }
            
            const sectionId = `section-${eventType}`;
            
            aggContainer.innerHTML = '<div class="agg-panel"><div class="section-toggle-bar" onclick="toggleAggregations()">▾ Aggregation Tables</div><div class="agg-content">' + buildAggregationTables(events, eventType) + '</div></div>';
        }
        
        function buildFilterBarHtml() {
            const hasFilters = Object.keys(currentFilters).length > 0;
            if (currentSearch.length === 0 && !hasFilters) return '';

            let html = '<div class="filter-bar"><span class="filter-label">🔍 Active:</span>';
            for (let i = 0; i < currentSearch.length; i++) {
                const term = currentSearch[i];
                html += `<span class="filter-chip">🔍 "${escapeHtml(term)}" <span class="filter-chip-remove" onclick="clearSearchTerm(${i})">&times;</span></span>`;
            }
            for (const [col, val] of Object.entries(currentFilters)) {
                html += `<span class="filter-chip">${col}: ${escapeHtml(val)} <span class="filter-chip-remove" onclick="clearFilter('${col}')">&times;</span></span>`;
            }
            html += '<button class="filter-clear-all" onclick="clearAllFilters()">Clear All</button></div>';
            return html;
        }

        function updateFilterBarVisibility() {
            const filterBarContainer = document.getElementById('filterBarContainer');
            if (!filterBarContainer) return;

            const hasFilters = Object.keys(currentFilters).length > 0;
            if (currentSearch.length > 0 || hasFilters) {
                filterBarContainer.innerHTML = buildFilterBarHtml();
                filterBarContainer.style.display = 'block';
            } else {
                filterBarContainer.innerHTML = '';
                filterBarContainer.style.display = 'none';
            }
        }
        
        let eventStats = {};
        
        function eventMatchesFilters(event) {
            if (Object.keys(currentFilters).length === 0) return true;
            for (const [col, val] of Object.entries(currentFilters)) {
                let extracted;
                if (col === 'Type' || col === 'Detail') {
                    const types = EVENT_TYPE_ICONS;
                    const allColumns = ALL_EVENTS_COLUMNS;
                    const allColIndex = allColumns.indexOf(col);
                    extracted = extractAllValue(event, col, allColIndex);
                } else {
                    extracted = extractValue(event, col, -1);
                }
                if (extracted !== val) return false;
            }
            return true;
        }

        function computeFilteredStats() {
            const stats = {};
            const events = allEvents.filter(e => e.event_type !== 'stats');
            for (const e of events) {
                if (eventMatchesFilters(e)) {
                    const type = e.event_type || 'unknown';
                    stats[type] = (stats[type] || 0) + 1;
                }
            }
            return stats;
        }

        function buildStats(filteredStats) {
            const grid = document.getElementById('statsGrid');
            const stats = [];
            const hasFilters = Object.keys(currentFilters).length > 0 || currentSearch.length > 0;
            
            eventTypes.forEach(type => {
                const total = baseEventStats[type] || 0;
                let filtered;
                if (type === 'filealerts') {
                    filtered = eventStats[type] || 0;
                } else {
                    filtered = filteredStats ? (filteredStats[type] || 0) : (eventStats[type] || 0);
                }
                stats.push({
                    id: type,
                    label: typeLabels[type] || type.toUpperCase(),
                    count: filtered,
                    total: total,
                    color: COLORS.EVENT[type] || COLORS.EVENT.tls
                });
            });
            
            const allFiltered = stats.reduce((a, s) => a + s.count, 0);
            const allTotal = Object.values(baseEventStats).reduce((a, b) => a + b, 0) - (baseEventStats['stats'] || 0);
            stats.push({
                id: 'all',
                label: 'All Events',
                count: allFiltered,
                total: allTotal,
                color: '#f0f6fc'
            });
            
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            const activeType = visibleSection ? visibleSection.id.replace('section-', '') : (stats[0] && stats[0].id);
            grid.innerHTML = stats.map(s => {
                const countDisplay = hasFilters ? `${s.count} / ${s.total}` : String(s.count);
                const isClickable = s.count > 0;
                const activeClass = s.id === activeType ? ' tab-active' : '';
                const disabledClass = isClickable ? '' : ' stat-disabled';
                const onclickAttr = isClickable ? `onclick="showTab('section-${s.id}', this)"` : '';
                return `
                    <div class="stat-card${activeClass}${disabledClass}" ${onclickAttr}>
                        <div class="stat-number" style="color: ${s.color}">${countDisplay}</div>
                        <div class="stat-label">${s.label}</div>
                    </div>
                `;
            }).join('');
        }
        
        function buildSections() {
            const sectionsEl = document.getElementById('sections');
            let html = '';
            
            eventTypes.forEach((type, i) => {
                const label = typeLabels[type] || type.toUpperCase();
                html += `<div class="section${i > 0 ? ' section-hidden' : ''}" id="section-${type}"><div class="section-header">${label}</div><div class="loading">Loading...</div></div>`;
            });
            
            html += '<div class="section section-hidden" id="section-all"><div class="section-header">All Events</div><div class="loading">Loading...</div></div>';
            sectionsEl.innerHTML = html;
            
        }
        
        function buildAllEvents() {
            const types = EVENT_TYPE_ICONS;
            const allColumns = ALL_EVENTS_COLUMNS;
            const sectionId = 'section-all';
            const sortedAll = [...allEvents].filter(e => e.event_type !== 'stats').sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
            
            if (sortedAll.length === 0) return;
            
            let filteredEvents = sortedAll;
            if (Object.keys(currentFilters).length > 0) {
                filteredEvents = sortedAll.filter(e => {
                    for (const [col, val] of Object.entries(currentFilters)) {
                        const colIndex = allColumns.indexOf(col);
                        const extracted = extractAllValue(e, col, colIndex);
                        if (extracted !== val) return false;
                    }
                    return true;
                });
            }
            
            const rows = filteredEvents.map(e => {
                const ts = (e.timestamp || '').slice(0, 19);
                const etype = e.event_type || '';
                const icon = types[etype] || '❓';
                const proto = e.proto || '';
                const srcIp = e.src_ip || '';
                const srcPort = e.src_port || '';
                const dstIp = e.dest_ip || '';
                const dstPort = e.dest_port || '';
                let detail = '';
                if (etype === 'alert') detail = e.alert?.signature || '';
                else if (etype === 'dns') detail = e.dns?.rrname || '';
                else if (etype === 'http') detail = (e.http?.http_method || '') + ' ' + (e.http?.url || '');
                else if (etype === 'tls') detail = e.tls?.sni || '';
                else if (etype === 'flow') detail = `${srcIp}:${srcPort} → ${dstIp}:${dstPort}`;
                else if (etype === 'ftp') detail = e.ftp?.command || '';
                else if (etype === 'anomaly') detail = e.anomaly?.message || '';
                else if (etype === 'fileinfo') detail = e.fileinfo?.filename || '';
                const formatted = formatEvent(e);
                return `<tr onclick="toggleRow(this)"><td class="timestamp">${escapeHtml(ts)}</td><td>${escapeHtml(icon)} ${escapeHtml(etype.toUpperCase())}</td><td><span class="badge badge-info">${escapeHtml(proto)}</span></td><td class="mono">${escapeHtml(srcIp)}</td><td class="mono">${escapeHtml(String(srcPort))}</td><td class="mono">${escapeHtml(dstIp)}</td><td class="mono">${escapeHtml(String(dstPort))}</td><td class="mono">${escapeHtml(detail)}</td></tr><tr class="detail-row"><td colspan="8"><div class="detail-content">${formatted}</div></td></tr>`;
            });
            
            const container = document.getElementById(sectionId);
            let html = '<div class="section-content">';
            if (rows.length === 0 && Object.keys(currentFilters).length > 0) {
                html += EMPTY_FILTER_STATE_HTML;
            } else {
                html += '<table><thead><tr>';
                allColumns.forEach(h => html += `<th>${h}</th>`);
                html += '</tr></thead><tbody>';
                rows.forEach(r => html += r);
                html += '</tbody></table>';
            }
            html += '</div>';
            
            container.innerHTML = html;
        }
        
        function buildAggregationsSectionAll() {
            const aggContainer = document.getElementById('aggregations');
            if (!aggContainer) return;
            
            const types = EVENT_TYPE_ICONS;
            const allColumns = ALL_EVENTS_COLUMNS;
            const sectionId = 'section-all';
            const sortedAll = [...allEvents].filter(e => e.event_type !== 'stats').sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
            
            let filteredEvents = sortedAll;
            if (Object.keys(currentFilters).length > 0) {
                filteredEvents = sortedAll.filter(e => {
                    for (const [col, val] of Object.entries(currentFilters)) {
                        const colIndex = allColumns.indexOf(col);
                        if (extractAllValue(e, col, colIndex) !== val) return false;
                    }
                    return true;
                });
            }
            
            if (!advancedMode) {
                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                return;
            }
            
            aggContainer.innerHTML = '<div class="agg-panel"><div class="section-toggle-bar" onclick="toggleAggregations()">▾ Aggregation Tables</div><div class="agg-content">' + buildAggregationTablesAll(filteredEvents, allColumns, types) + '</div></div>';
        }
        
        function extractAllValue(e, col, colIndex) {
            if (col === 'Type') return (e.event_type || '').toUpperCase();
            if (col === 'Command') return e.ftp?.command || '';
            if (col === 'Message') return e.anomaly?.message || '';
            return extractValue(e, col, colIndex);
        }
        
        function buildAggregationTablesCore(events, columns, sectionId, extractFn) {
            if (!events || events.length === 0) return '';
            
            const excludeCols = ['Time'];
            const aggCols = columns.filter(c => !excludeCols.includes(c) && !hiddenAggregations.has(sectionId + ':' + c));
            
            let html = '<div class="agg-grid">';
            
            for (const col of aggCols) {
                const colIndex = columns.indexOf(col);
                const counts = {};
                
                for (const e of events) {
                    const val = extractFn(e, col, colIndex);
                    const key = val || '(empty)';
                    counts[key] = (counts[key] || 0) + 1;
                }
                
                const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, CONFIG.AGGREGATION_TOP_N);
                
                html += `<div class="section agg-section" data-col="${col}"><div class="section-content"><div class="agg-table">
                    <div class="agg-header"><span>${col}</span><button class="agg-close" onclick="hideAggregationTable('${sectionId}', '${col.replace(/'/g, "\\'")}')" title="Hide">&times;</button></div>
                    <table>
                        <thead><tr><th style="width:60px;text-align:right;">Count</th><th>Value</th></tr></thead>
                        <tbody>`;
                
                for (const [val, count] of sorted) {
                    const displayVal = val === '(empty)' ? '' : val;
                    const escapedVal = escapeHtml(val);
                    const filterVal = val === '(empty)' ? '' : val;
                    html += `<tr class="agg-row" onclick="applyFilter('${sectionId}', '${col.replace(/'/g, "\\'")}', '${String(filterVal).replace(/'/g, "\\'")}')">
                        <td style="text-align:right;color:#8b949e;">${count}</td>
                        <td class="agg-cell" title="${escapedVal}">${escapedVal}</td>
                    </tr>`;
                }
                
                html += `</tbody></table></div></div></div>`;
            }
            
            html += '</div>';
            return html;
        }
        
        function buildAggregationTablesAll(events, columns, types) {
            return buildAggregationTablesCore(events, columns, 'section-all', extractAllValue);
        }
        
        function extractValue(e, col, colIndex) {
            switch(col) {
                case 'Protocol': return e.proto || '';
                case 'Source IP': return e.src_ip || '';
                case 'Source Port': return String(e.src_port || '');
                case 'Dest IP': return e.dest_ip || '';
                case 'Dest Port': return String(e.dest_port || '');
                case 'Alert': return e.alert?.signature || '';
                case 'Category': return e.alert?.category || '';
                case 'Severity': return 'Sev ' + (e.alert?.severity || 0);
                case 'Query': return e.dns?.rrname || '';
                case 'Type': return e.dns?.rrtype || '';
                case 'Method': return e.http?.http_method || '';
                case 'Host': return e.http?.hostname || '';
                case 'URL': return e.http?.url || '';
                case 'Status': return String(e.http?.status || '');
                case 'User-Agent': return (e.http?.http_user_agent || '').slice(0, 50);
                case 'SNI / Host': return e.tls?.sni || '-';
                case 'Version': return e.tls?.version || '-';
                case 'Subject': return (e.tls?.subject || '-').slice(0, 40);
                case 'Issuer': return (e.tls?.issuerdn || '-').slice(0, 40);
                case 'Pkts →': return String(e.flow?.pkts_toserver || 0);
                case 'Pkts ←': return String(e.flow?.pkts_toclient || 0);
                case 'Bytes →': return String(e.flow?.bytes_toserver || 0);
                case 'Bytes ←': return String(e.flow?.bytes_toclient || 0);
                case 'State': return e.flow?.state || '';
                case 'Alerted': return e.flow?.alerted ? 'Yes' : 'No';
                case 'Filename': return e.fileinfo?.filename || '';
                case 'Rule Name': return e.filealerts?.rule_name || '';
                case 'Classification': {
                    return getClassificationLabel(e.filealerts?.classification || 'informational');
                }
                case 'Tags': return (e.filealerts?.tags || []).join(', ');
                case 'Detail': {
                    const etype = e.event_type || '';
                    if (etype === 'alert') return e.alert?.signature || '';
                    if (etype === 'dns') return e.dns?.rrname || '';
                    if (etype === 'http') return (e.http?.http_method || '') + ' ' + (e.http?.url || '');
                    if (etype === 'tls') return e.tls?.sni || '';
                    if (etype === 'flow') return `${e.src_ip || ''}:${e.src_port || ''} → ${e.dest_ip || ''}:${e.dest_port || ''}`;
                    if (etype === 'ftp') return e.ftp?.command || '';
                    if (etype === 'anomaly') return e.anomaly?.message || '';
                    if (etype === 'fileinfo') return e.fileinfo?.filename || '';
                    return '';
                }
                default: return '';
            }
        }
        
        function buildAggregationTables(events, eventType) {
            return buildAggregationTablesCore(events, getColumnsForType(eventType), 'section-' + eventType, extractValue);
        }
        
        let allEvents = [];
        let sections = {};
        let eventTypes = [];
        let currentMd5 = '';
          let currentFileName = '';
          let currentFilters = {};
          let currentSearch = [];
          let advancedMode = false;
          let diagramMode = true;
          let hiddenAggregations = new Set();
          let baseEventStats = {};

        const EVENT_TYPE_ICONS = { alert: '🔴', dns: '🟢', http: '🟠', tls: '🔵', flow: '🟣', ftp: '📁', anomaly: '⚠️', fileinfo: '📄', filealerts: '🚨' };
        const ALL_EVENTS_COLUMNS = ['Time', 'Type', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Detail'];
        const EMPTY_FILTER_STATE_HTML = '<div style="padding: 40px; text-align: center; color: #8b949e; font-size: 0.95rem;">🔍 No events match the current filters</div>';
        const AGG_COLLAPSED_HTML = '<div class="agg-panel"><div class="section-toggle-bar" onclick="toggleAggregations()">▸ Aggregation Tables</div></div>';

        function hideAggregationTable(sectionId, col) {
            hiddenAggregations.add(sectionId + ':' + col);
            document.querySelectorAll(`.agg-section[data-col="${col}"]`).forEach(el => {
                el.style.display = 'none';
            });
            const anyVisible = document.querySelectorAll('.agg-section:not([style*="display: none"])').length > 0;
            if (!anyVisible) {
                advancedMode = false;
                const aggContainer = document.getElementById('aggregations');
                if (aggContainer) {
                    aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                }
            }
        }

        function getColumnNameFromSankeyColumn(col) {
            return ['Source IP', 'Dest IP', 'Dest Port'][col] || '';
        }

        function refreshCurrentView(sectionId, eventType) {
            updateFilterBarVisibility();
            buildStats(computeFilteredStats());
            if (eventType === 'all') {
                buildAllEvents();
                buildAggregationsSectionAll();
            } else {
                buildSection(eventType, sections[eventType]);
                const filtered = getFilteredEvents(sectionId, sections[eventType], eventType);
                buildAggregationsSection(eventType, filtered);
            }
            updateSankeyDiagram();
        }

        function applyFilters(sectionId, filters) {
            for (const f of filters) {
                currentFilters[f.column] = f.value;
            }
            const eventType = sectionId.replace('section-', '');
            refreshCurrentView(sectionId, eventType);
        }

        function applyFilter(sectionId, columnName, value) {
            applyFilters(sectionId, [{column: columnName, value: value}]);
        }

        function clearFilter(columnName) {
            delete currentFilters[columnName];
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            if (!visibleSection) return;
            const eventType = visibleSection.id.replace('section-', '');
            refreshCurrentView(visibleSection.id, eventType);
        }

        async function clearAllFilters() {
            currentFilters = {};
            currentSearch = [];
            const input = document.getElementById('searchInput');
            if (input) input.value = '';
            updateFilterBarVisibility();
            await refreshAnalysisData();
        }
        
        function getFilteredEvents(sectionId, events, eventType) {
            if (Object.keys(currentFilters).length === 0) return events;
            
            if (eventType === 'all') {
                const types = EVENT_TYPE_ICONS;
                const allColumns = ALL_EVENTS_COLUMNS;
                return events.filter(e => {
                    for (const [col, val] of Object.entries(currentFilters)) {
                        const colIndex = allColumns.indexOf(col);
                        if (extractAllValue(e, col, colIndex) !== val) return false;
                    }
                    return true;
                });
            }
            
            const columns = getColumnsForType(eventType);
            return events.filter(e => {
                for (const [col, val] of Object.entries(currentFilters)) {
                    const colIndex = columns.indexOf(col);
                    if (extractValue(e, col, colIndex) !== val) return false;
                }
                return true;
            });
        }
        
        async function performSearch() {
            const input = document.getElementById('searchInput');
            const text = input ? input.value.trim() : '';
            if (!text) return;

            const terms = text.match(/"[^"]+"|\S+/g) || [];
            for (const t of terms) {
                const term = t.replace(/^"|"$/g, '').trim();
                if (term && !currentSearch.includes(term)) {
                    currentSearch.push(term);
                }
            }

            if (input) input.value = '';
            updateFilterBarVisibility();
            await refreshAnalysisData();
        }

        async function clearSearch() {
            currentSearch = [];
            const input = document.getElementById('searchInput');
            if (input) input.value = '';
            updateFilterBarVisibility();
            await refreshAnalysisData();
        }

        async function clearSearchTerm(index) {
            currentSearch.splice(index, 1);
            updateFilterBarVisibility();
            await refreshAnalysisData();
        }

        async function refreshAnalysisData() {
            if (!currentMd5) return;
            showLoading(currentSearch.length > 0 ? 'Searching...' : 'Loading events...');

            const qParam = currentSearch.length > 0 ? currentSearch.map(t => '&q=' + encodeURIComponent(t)).join('') : '';

            const [statsResp, baseStatsResp] = await Promise.all([
                fetch('/api/stats?md5=' + currentMd5 + qParam + '&t=' + Date.now()),
                fetch('/api/stats?md5=' + currentMd5 + '&t=' + Date.now())
            ]);
            eventStats = await statsResp.json();
            baseEventStats = await baseStatsResp.json();

            const types = sortEventTypes(Object.keys(baseEventStats).filter(t => t !== 'stats' && t !== 'all'));
            eventTypes = types;

            const eventsResp = await fetch('/api/events?md5=' + currentMd5 + '&limit=' + CONFIG.MAX_QUERY_LIMIT + qParam + '&t=' + Date.now());
            allEvents = await eventsResp.json();

            const isFileOnly = !eventTypes.includes('alert');
            
            if (isFileOnly) {
                document.body.classList.add('file-analysis');
                document.querySelectorAll('.file-info-card').forEach(c => c.remove());
                document.getElementById('sections').innerHTML = '';
                tabDataCache = {};
                buildFileInfoCard();
                
                const fileAlertsEvents = allEvents.filter(e => e.event_type === 'filealerts');
                if (fileAlertsEvents.length > 0) {
                    buildFileAlertCards(fileAlertsEvents);
                } else {
                    document.getElementById('sections').innerHTML = '<div class="no-matches">No YARA matches</div>';
                }
            } else {
                document.body.classList.remove('file-analysis');
                buildStats(computeFilteredStats());
                
                // Remember active section before rebuild
                const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
                const activeType = visibleSection ? visibleSection.id.replace('section-', '') : '';

                document.getElementById('sections').innerHTML = '';
                tabDataCache = {};
                buildSections();

                // Restore active section after rebuild
                if (activeType && activeType !== eventTypes[0]) {
                    document.querySelectorAll('.section').forEach(s => s.classList.add('section-hidden'));
                    const sectionEl = document.getElementById('section-' + activeType);
                    if (sectionEl) {
                        sectionEl.classList.remove('section-hidden');
                        loadTabData(activeType, null);
                    }
                } else if (eventTypes[0]) {
                    loadTabData(eventTypes[0], null);
                }
            }

            updateFilterBarVisibility();
            hideLoading();
        }

        async function loadAnalysis(md5) {
            try {
                const resp = await fetch('/api/load-analysis?md5=' + md5);
                const result = await resp.json();
                
                if (result.error) {
                    showError(result.error);
                    await showWelcome();
                    return;
                }
                
                if (result.success) {
                    currentMd5 = md5;
                    currentFileName = result.file_name || md5;
                    document.title = 'OhMyPCAP - ' + currentFileName;
                    const urlParams = new URLSearchParams(window.location.search);
                    urlParams.set('file', md5);
                    const newUrl = window.location.pathname + '?' + urlParams.toString();
                    if (window.location.href !== window.location.origin + newUrl) {
                        history.replaceState({}, '', newUrl);
                    }
                    
                    allEvents = [];
                    sections = {};
                    eventTypes = [];
                    currentFilters = {};
                    currentSearch = [];
                    hiddenAggregations = new Set();
                    tabDataCache = {};
                    clearAnalysisContainers();
                    document.getElementById('searchInput').value = '';
                    
                    showLoading('Loading events...');
                    
                    const statsResp = await fetch('/api/stats?md5=' + md5 + '&t=' + Date.now());
                    eventStats = await statsResp.json();
                    baseEventStats = {...eventStats};
                    
                    const types = sortEventTypes(Object.keys(baseEventStats).filter(t => t !== 'stats' && t !== 'all'));
                    // eventTypes should not include 'all' - it's added separately by buildStats()
                    eventTypes = types;
                    
                    const eventsResp = await fetch('/api/events?md5=' + md5 + '&limit=' + CONFIG.MAX_QUERY_LIMIT + '&t=' + Date.now());
                    allEvents = await eventsResp.json();
                    
                    eventTypes = types;
                    
                    buildStats(computeFilteredStats());
                    
                    if (allEvents.length === 0) {
                        hideLoading();
                        return;
                    }
                    
                    // Get date range from non-stats events
                    const mainEvents = allEvents.filter(e => e.event_type !== 'stats');
                    const ts = mainEvents.map(e => e.timestamp).filter(Boolean).sort();
                    const dateDisplay = ts.length > 0 && ts[0] === ts[ts.length - 1]
                        ? ts[0].slice(0, 19)
                        : `${ts[0]?.slice(0, 19) || ''} to ${ts[ts.length-1]?.slice(0, 19) || ''}`;
                    
                    const isFileOnly = !eventTypes.includes('alert');
                    
                    if (isFileOnly) {
                        document.body.classList.add('file-analysis');
                    } else {
                        document.body.classList.remove('file-analysis');
                    }
                    
                    const helpText = isFileOnly
                        ? '<span style="color: #58a6ff;">💡</span> YARA scan results for the uploaded file. Review the File Info card for metadata and the File Alerts table for any matches found by the YARA rules.'
                        : '<span style="color: #58a6ff;">💡</span> Start by reviewing all alerts and then you can change to one of the other data types like DNS, HTTP, or TLS. Filter using the search bar, sankey diagram, or aggregation tables. When you find something interesting, you can drill into the row in the data table at the bottom. This will allow you to see the ASCII transcript and hexdump and optionally download the PCAP file for that stream.';
                    
                    document.getElementById('headerContent').innerHTML = `
                        <div style="background: #161b22; padding: 12px 20px; border-radius: 8px; border: 1px solid #30363d; flex: 1;">
                            <div style="display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;">
                                <a href="#" onclick="showWelcome(); return false;" style="color: #58a6ff; text-decoration: none; font-weight: 600; white-space: nowrap; display: inline-flex; align-items: center; gap: 6px;">
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                                        <line x1="19" y1="12" x2="5" y2="12"></line>
                                        <polyline points="12 19 5 12 12 5"></polyline>
                                    </svg>
                                    Back to Overview
                                </a>
                                <span style="color: #f0f6fc; font-weight: 600; white-space: nowrap;">📄 ${currentFileName}</span>
                                <span style="color: #8b949e; font-size: 0.9rem; white-space: nowrap;">📁 ${currentMd5}</span>
                                <span style="color: #8b949e; font-size: 0.9rem; white-space: nowrap;">📅 ${dateDisplay}</span>
                            </div>
                            <div style="color: #8b949e; font-size: 0.8rem; margin-top: 8px; text-align: center;">
                                ${helpText}
                            </div>
                        </div>
                     `;
                    showAnalysisUI();
                    updateFilterBarVisibility();
                    
                    if (isFileOnly) {
                        // File-only analysis: render simplified UI
                        buildFileInfoCard();
                        document.getElementById('sections').innerHTML = '';
                        tabDataCache = {};
                        
                        // Build filealerts section directly
                        const fileAlertsEvents = allEvents.filter(e => e.event_type === 'filealerts');
                        if (fileAlertsEvents.length > 0) {
                            buildFileAlertCards(fileAlertsEvents);
                        } else {
                            document.getElementById('sections').innerHTML = '<div class="no-matches">No YARA matches</div>';
                        }
                    } else {
                        // PCAP analysis: full layout
                        buildSections();
                        if (eventTypes[0]) loadTabData(eventTypes[0]);
                        
                        const sankeyPanel = document.getElementById('sankeyPanel');
                        if (sankeyPanel) {
                            sankeyPanel.style.display = '';
                            updateSankeyDiagram();
                        }
                        
                        const aggContainer = document.getElementById('aggregations');
                        if (aggContainer) {
                            if (advancedMode) {
                                buildAggregationsSectionAll();
                            } else {
                                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                            }
                        }
                    }
                    
                    hideLoading();
                    
                    // Reset URL field for next analysis
                    const urlInput = document.getElementById('pcapUrl');
                    if (urlInput) {
                        urlInput.value = 'https://www.malware-traffic-analysis.net/2026/02/03/2026-02-03-GuLoader-for-AgentTesla-style-infection-with-FTP-data-exfil.pcap.zip';
                    }
                }
            } catch(err) {
                console.error('loadAnalysis error:', err);
                console.error('loadAnalysis error stack:', err.stack);
                console.error('loadAnalysis error name:', err.name);
            }
        }
        
        async function loadFromUrl() {
            const urlInput = document.getElementById('pcapUrl');
            const url = urlInput.value.trim();
            const exampleUrl = 'https://www.malware-traffic-analysis.net/2026/02/03/2026-02-03-GuLoader-for-AgentTesla-style-infection-with-FTP-data-exfil.pcap.zip';
            
            if (!url) {
                showError('Please enter a URL');
                return;
            }
            
            showLoading('Downloading PCAP... (0s)');
            const downloadStart = Date.now();
            let downloadInterval = setInterval(() => {
                const elapsedSec = Math.floor((Date.now() - downloadStart) / 1000);
                showLoading(`Downloading PCAP... (${elapsedSec}s)`);
            }, 1000);

            try {
                const resp = await fetch('/api/load-url', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                const result = await resp.json();
                clearInterval(downloadInterval);

                if (result.status === 'processing') {
                    await checkStatus(result.md5, result.phase || 'network');
                    urlInput.value = exampleUrl;
                } else if (result.status === 'ready') {
                    hideLoading();
                    await loadAnalysis(result.md5);
                    urlInput.value = exampleUrl;
                } else {
                    hideLoading();
                    showError(result.error || 'Unknown error');
                }
            } catch(err) {
                clearInterval(downloadInterval);
                hideLoading();
                showError(err.message);
            }
        }
        
        async function uploadPcap(droppedFile) {
            const fileInput = document.getElementById('pcapUpload');
            const file = droppedFile || fileInput.files[0];
            if (!file) return;

            showLoading('Uploading file... (0s)');
            const uploadStart = Date.now();
            let uploadInterval = setInterval(() => {
                const elapsedSec = Math.floor((Date.now() - uploadStart) / 1000);
                showLoading(`Uploading file... (${elapsedSec}s)`);
            }, 1000);

            const formData = new FormData();
            formData.append('pcap', file);

            try {
                const resp = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                const result = await resp.json();
                clearInterval(uploadInterval);

                if (!resp.ok || result.error) {
                    hideLoading();
                    showError(result.error || 'Upload failed');
                    fileInput.value = '';
                    return;
                }

                if (result.status === 'ready') {
                    hideLoading();
                    await loadAnalysis(result.md5);
                } else if (result.status === 'processing') {
                    await checkStatus(result.md5, result.phase || 'network');
                }
            } catch(err) {
                clearInterval(uploadInterval);
                hideLoading();
                showError(err.message);
            }
            
            fileInput.value = '';
        }
        
        function handleDragOver(e) {
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.add('drop-zone-active');
        }
        
        function handleDragLeave(e) {
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.remove('drop-zone-active');
        }
        
        function handleDrop(e) {
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.remove('drop-zone-active');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                uploadPcap(files[0]);
            }
        }
        
        async function checkStatus(md5, initialPhase = 'network') {
            const phaseMessages = {
                'network': 'Analyzing network traffic...',
                'files': 'Analyzing files...',
                'importing': 'Importing data...'
            };
            
            const startTime = Date.now();
            let currentPhase = initialPhase;
            let elapsedInterval = null;
            
            // Show initial message immediately
            showLoading(`${phaseMessages[currentPhase]} (0s)`);
            
            // Local timer updates elapsed time every 1s without hitting the server
            elapsedInterval = setInterval(() => {
                const elapsedSec = Math.floor((Date.now() - startTime) / CONFIG.POLLING_INTERVAL_MS);
                const msg = phaseMessages[currentPhase] || 'Analyzing file...';
                showLoading(`${msg} (${elapsedSec}s)`);
            }, CONFIG.POLLING_INTERVAL_MS);
            
            for (let i = 0; i < CONFIG.MAX_POLLING_ATTEMPTS; i++) {
                await new Promise(r => setTimeout(r, 2000));
                
                try {
                    const resp = await fetch('/api/check-status', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({md5: md5})
                    });
                    const result = await resp.json();
                    
                    if (result.status === 'error') {
                        clearInterval(elapsedInterval);
                        hideLoading();
                        showError(result.message || 'Analysis failed');
                        return;
                    }

                    if (result.status === 'ready') {
                        clearInterval(elapsedInterval);
                        hideLoading();
                        await loadAnalysis(md5);
                        return;
                    }
                    
                    if (result.status === 'processing') {
                        currentPhase = result.phase || 'network';
                    }
                } catch(err) {
                    console.error('Status check error:', err);
                }
            }
            
            clearInterval(elapsedInterval);
            hideLoading();
            showError('Analysis timed out. The file may be very large or analysis may have encountered an error.');
        }
        
        let pendingDelete = null;
        let pendingReanalyze = null;
        
        function openDeleteAnalysis(md5, name) {
            pendingDelete = { md5, name };
            document.getElementById('deleteFileName').textContent = name;
            document.getElementById('deleteConfirmModal').classList.add('active');
        }
        
        function closeDeleteModal() {
            pendingDelete = null;
            document.getElementById('deleteConfirmModal').classList.remove('active');
        }
        
        function showError(message) {
            document.getElementById('errorMessage').textContent = message;
            document.getElementById('errorModal').classList.add('active');
        }
        
        function closeErrorModal() {
            document.getElementById('errorModal').classList.remove('active');
        }
        
        async function confirmDelete() {
            if (!pendingDelete) return;
            
            const { md5, name } = pendingDelete;
            pendingDelete = null;
            document.getElementById('deleteConfirmModal').classList.remove('active');
            
            try {
                const resp = await fetch('/api/delete-analysis?md5=' + md5);
                const result = await resp.json();
                if (result.success) {
                    showWelcome();
                } else {
                    showError(result.error || 'Could not delete');
                }
            } catch(err) {
                showError(err.message);
            }
        }
        
        function openReanalyzeModal(md5, name) {
            pendingReanalyze = { md5, name };
            document.getElementById('reanalyzeFileName').textContent = name;
            document.getElementById('reanalyzeConfirmModal').classList.add('active');
        }
        
        function closeReanalyzeModal() {
            pendingReanalyze = null;
            document.getElementById('reanalyzeConfirmModal').classList.remove('active');
        }
        
        async function confirmReanalyze() {
            if (!pendingReanalyze) return;
            const { md5, name } = pendingReanalyze;
            pendingReanalyze = null;
            closeReanalyzeModal();
            
            showLoading('Re-analyzing ' + name + '...');
            try {
                const resp = await fetch('/api/reanalyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({md5: md5})
                });
                const result = await resp.json();
                if (result.error) {
                    hideLoading();
                    showError(result.error);
                    return;
                }
                if (result.status === 'processing') {
                    await checkStatus(md5);
                } else {
                    hideLoading();
                }
            } catch(err) {
                hideLoading();
                showError(err.message);
            }
        }
        
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                if (diagramMode && currentMd5) {
                    updateSankeyDiagram();
                }
            }, CONFIG.SEARCH_DEBOUNCE_MS);
        });

        async function init() {
            try {
                // Fetch and display version from server
                try {
                    const verResp = await fetch('/api/version');
                    if (verResp.ok) {
                        const verData = await verResp.json();
                        const link = document.getElementById('footerVersionLink');
                        if (link && verData.version) {
                            link.textContent = 'OhMyPCAP ' + verData.version;
                        }
                    }
                } catch(verErr) {
                    // Ignore version fetch errors — footer shows placeholder
                }

                // Check for file query parameter (backward compatible with ?pcap=)
                const urlParams = new URLSearchParams(window.location.search);
                const fileMd5 = urlParams.get('file') || urlParams.get('pcap');
                
                if (fileMd5) {
                    await loadAnalysis(fileMd5);
                } else {
                    await showWelcome();
                }
            } catch(err) {
                console.error('Init error:', err);
                
            }
        }
        
        init().catch(err => {
            console.error('Init error:', err);
            console.error('Init error stack:', err.stack);
            console.error('Init error names:', err.name);
        });
