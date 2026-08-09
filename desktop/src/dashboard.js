// Native activity dashboard, rendered as an in-window view of the Tauri app.
// Data comes from #[tauri::command] IPC calls (no HTTP / no 127.0.0.1),
// CSV export uses a native save dialog.
// This document is loaded in a same-origin iframe, so the Tauri bridge lives on
// the parent window; fall back to it when this frame wasn't injected directly.
const __tauri =
    window.__TAURI__ ||
    (window.parent && window.parent.__TAURI__) ||
    (window.top && window.top.__TAURI__);
const { invoke } = __tauri.core;

// Ask the host window to return to the metrics home. No-op when opened standalone.
function goHome() {
    try {
        window.parent.postMessage({ type: "tenby10-exit-dashboard" }, "*");
    } catch (e) {
        /* not embedded */
    }
}


        let globalSlots = [];
        let daysMap = {};
        let availableDates = [];
        let currentDateKey = null;
        let currentViewMode = 'daily';
        let weekStartDay = parseInt(localStorage.getItem('weekStartDay') || '1', 10); // 1 = Monday, 0 = Sunday

        // Fetch dashboard data
        async function fetchDashboardData() {
            try {
                const slots = await invoke('dashboard_slots');
                const pendingSlots = await invoke('dashboard_pending_slots');

                globalSlots = slots || [];

                if (pendingSlots) {
                    pendingSlots.forEach(slotStart => {
                        globalSlots.push({
                            slot_start: slotStart,
                            is_pending: true,
                            focus_score: 0,
                            active_segments: 0,
                            idle_segments: 0,
                            total_keystrokes: 0,
                            total_clicks: 0,
                            app_categories: {},
                        });
                    });
                }
                
                processSlots();
                
                // Determine initial date
                const urlParams = getParamsFromUrl();
                if (urlParams.date) {
                    currentDateKey = urlParams.date;
                } else if (availableDates.length > 0) {
                    // Default to the most recent date with data
                    currentDateKey = availableDates[availableDates.length - 1];
                } else {
                    // Fallback to today's date in YYYY-MM-DD local format
                    const today = new Date();
                    const year = today.getFullYear();
                    const month = String(today.getMonth() + 1).padStart(2, '0');
                    const day = String(today.getDate()).padStart(2, '0');
                    currentDateKey = `${year}-${month}-${day}`;
                }
                
                if (urlParams.tab) {
                    currentViewMode = urlParams.tab;
                }
                
                document.getElementById('week-start-select').value = weekStartDay.toString();
                
                document.querySelectorAll('.view-tab').forEach(el => el.classList.remove('active'));
                const activeTab = document.getElementById(`tab-${currentViewMode}`);
                if (activeTab) activeTab.classList.add('active');
                
                document.getElementById('day-view-container').style.display = currentViewMode === 'daily' ? 'block' : 'none';
                document.getElementById('week-view-container').style.display = currentViewMode === 'weekly' ? 'block' : 'none';
                document.getElementById('month-view-container').style.display = currentViewMode === 'monthly' ? 'block' : 'none';
                
                renderCurrentView();
            } catch (err) {
                console.error("Error fetching dashboard data", err);
                document.getElementById('day-view-container').innerHTML = 
                    `<div class="empty-timeline">Failed to load data. Confirm SQLite has logged active hours.</div>`;
            }
        }

        function processSlots() {
            daysMap = {};
            globalSlots.forEach(slot => {
                const date = new Date(slot.slot_start * 1000);
                const year = date.getFullYear();
                const month = String(date.getMonth() + 1).padStart(2, '0');
                const day = String(date.getDate()).padStart(2, '0');
                const dateKey = `${year}-${month}-${day}`;
                
                if (!daysMap[dateKey]) {
                    daysMap[dateKey] = {
                        dateKey: dateKey,
                        formattedDate: date.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
                        slots: [],
                        totalActiveSegments: 0,
                        // A slot is "logged" iff it holds >=1 productive minute (focus_score > 0).
                        // Active time = totalLoggedSlots * 10, so it reconstructs by counting
                        // 10-minute slots and matches the fat client's get_today_metrics exactly.
                        totalLoggedSlots: 0,
                        sumFocusScore: 0,
                    };
                }
                const entry = daysMap[dateKey];
                entry.slots.push(slot);
                entry.totalActiveSegments += slot.active_segments;
                if (slot.focus_score > 0) entry.totalLoggedSlots += 1;
                entry.sumFocusScore += slot.focus_score;
            });

            availableDates = Object.keys(daysMap).sort();
        }

        function getParamsFromUrl() {
            // Native window: no query string / navigable URL. State lives in memory.
            return { date: null, tab: null };
        }

        function updateUrl() {
            // No-op: the dashboard renders in a native window with no address bar.
        }

        function updateWeekStart(val) {
            weekStartDay = parseInt(val, 10);
            localStorage.setItem('weekStartDay', weekStartDay);
            renderCurrentView();
        }

        function switchView(mode) {
            currentViewMode = mode;
            document.querySelectorAll('.view-tab').forEach(el => el.classList.remove('active'));
            const activeTab = document.getElementById(`tab-${mode}`);
            if (activeTab) activeTab.classList.add('active');
            
            document.getElementById('day-view-container').style.display = mode === 'daily' ? 'block' : 'none';
            document.getElementById('week-view-container').style.display = mode === 'weekly' ? 'block' : 'none';
            document.getElementById('month-view-container').style.display = mode === 'monthly' ? 'block' : 'none';
            
            const todayBtn = document.getElementById('today-btn');
            const dateLabel = document.getElementById('date-picker-label');
            const datePicker = document.getElementById('date-picker');
            const weekStartContainer = document.getElementById('week-start-container');
            
            if (mode === 'daily') {
                todayBtn.innerText = 'Today';
                dateLabel.innerText = 'Select Date:';
                datePicker.type = 'date';
                weekStartContainer.style.display = 'none';
            } else if (mode === 'weekly') {
                todayBtn.innerText = 'This Week';
                dateLabel.innerText = 'Jump to Week of:';
                datePicker.type = 'date';
                weekStartContainer.style.display = 'flex';
            } else if (mode === 'monthly') {
                todayBtn.innerText = 'This Month';
                dateLabel.innerText = 'Select Month:';
                datePicker.type = 'month';
                weekStartContainer.style.display = 'flex';
            }
            
            updateUrl();
            renderCurrentView();
        }

        function navigateToDate(dateStr) {
            currentDateKey = dateStr;
            updateUrl();
            renderCurrentView();
        }

        function navigateToToday() {
            const today = new Date();
            const year = today.getFullYear();
            const month = String(today.getMonth() + 1).padStart(2, '0');
            const day = String(today.getDate()).padStart(2, '0');
            navigateToDate(`${year}-${month}-${day}`);
        }

        function stepDate(amount, unit) {
            const dateParts = currentDateKey.split('-');
            const current = new Date(parseInt(dateParts[0]), parseInt(dateParts[1]) - 1, parseInt(dateParts[2]));
            if (unit === 'day') {
                current.setDate(current.getDate() + amount);
            } else if (unit === 'month') {
                current.setMonth(current.getMonth() + amount);
            }
            const year = current.getFullYear();
            const month = String(current.getMonth() + 1).padStart(2, '0');
            const day = String(current.getDate()).padStart(2, '0');
            navigateToDate(`${year}-${month}-${day}`);
        }

        function prevDay() {
            if (currentViewMode === 'daily') {
                stepDate(-1, 'day');
            } else if (currentViewMode === 'weekly') {
                stepDate(-7, 'day');
            } else if (currentViewMode === 'monthly') {
                stepDate(-1, 'month');
            }
        }

        function nextDay() {
            if (currentViewMode === 'daily') {
                stepDate(1, 'day');
            } else if (currentViewMode === 'weekly') {
                stepDate(7, 'day');
            } else if (currentViewMode === 'monthly') {
                stepDate(1, 'month');
            }
        }

        function datePickerChanged(input) {
            if (input.value) {
                if (currentViewMode === 'monthly') {
                    navigateToDate(`${input.value}-01`);
                } else {
                    navigateToDate(input.value);
                }
            }
        }

        function getFormattedDate(dateKey) {
            const dateParts = dateKey.split('-');
            const date = new Date(dateParts[0], dateParts[1] - 1, dateParts[2]);
            return date.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        }


        function escapeHtml(str) {
            if (!str) return '';
            return str
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function showSlotDetails(timestamp, event) {
            if (event) event.stopPropagation();
            
            // Format start and end time for title
            const date = new Date(timestamp * 1000);
            const startStr = date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
            const endDate = new Date((timestamp + 600) * 1000);
            const endStr = endDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
            document.getElementById('dialog-slot-title').innerText = `Slot Details: ${startStr} - ${endStr}`;
            
            // Render LLM Reasoning if available
            const slot = globalSlots.find(s => s.slot_start === timestamp);
            if (slot && slot.llm_reasoning) {
                document.getElementById('dialog-llm-reasoning').innerHTML = `
                    <div style="margin-bottom: 0.5rem; padding: 1rem; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px;">
                        <h4 style="font-size: 0.7rem; text-transform: uppercase; color: var(--accent-green); margin-bottom: 0.5rem;">AI Auditor Reasoning</h4>
                        <p style="font-size: 0.85rem; line-height: 1.4; color: #fff;">${escapeHtml(slot.llm_reasoning)}</p>
                    </div>
                `;
            } else {
                document.getElementById('dialog-llm-reasoning').innerHTML = '';
            }

            // Fetch and render minute-by-minute logs
            const listContainer = document.getElementById('dialog-details-list');
            listContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem;">Loading activity details...</div>`;
            
            invoke('dashboard_slot_details', { start: timestamp })
                .then(details => {
                    if (!details || details.length === 0) {
                        listContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; text-align: center; padding: 2rem 0;">No active minute logs found for this slot.</div>`;
                        return;
                    }
                    
                    listContainer.innerHTML = details.map(item => {
                        const mDate = new Date(item.timestamp * 1000);
                        const mTimeStr = mDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
                        
                        let warningBadge = '';
                        if (item.low_entropy) {
                            warningBadge = `<span class="badge badge-focus red" style="font-size:0.6rem; padding: 1px 4px; margin-left: 6px;">⚠️ Tamper Flag</span>`;
                        }
                        
                        let stateColor = item.state === 'Productive' ? 'rgba(16, 185, 129, 0.2)' : 
                                         item.state === 'Meeting' ? 'rgba(59, 130, 246, 0.2)' :
                                         item.state === 'Waste' ? 'rgba(239, 68, 68, 0.2)' : 
                                         'rgba(156, 163, 175, 0.1)';
                        let stateText = item.state === 'Productive' ? 'var(--accent-green)' : 
                                        item.state === 'Meeting' ? 'var(--accent-blue)' :
                                        item.state === 'Waste' ? 'var(--accent-red)' : 
                                        'var(--text-muted)';
                        
                        return `
                            <div class="detail-item-card" style="border-left: 3px solid ${stateText};">
                                <div class="detail-item-meta" style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                                    <div>
                                        <span class="detail-item-time">${mTimeStr}${warningBadge}</span>
                                        <span class="badge" style="background: ${stateColor}; color: ${stateText}; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; margin-left: 8px;">${item.state}</span>
                                    </div>
                                    <span class="detail-item-inputs">Keys: ${item.keystroke_count} | Clicks: ${item.mouse_click_count} | Scrolls: ${item.scroll_event_count}</span>
                                </div>
                                <div class="detail-item-app">${escapeHtml(item.active_app_name)}</div>
                                <div class="detail-item-title">${escapeHtml(item.active_window_title)}</div>
                            </div>
                        `;
                    }).join('');
                })
                .catch(err => {
                    console.error("Error fetching slot details:", err);
                    listContainer.innerHTML = `<div style="color: var(--accent-red); font-size: 0.8rem; text-align: center; padding: 2rem 0;">Failed to load activity details.</div>`;
                });
            
            const dialog = document.getElementById('slot-dialog');
            dialog.showModal();
        }

        function closeSlotDialog() {
            const dialog = document.getElementById('slot-dialog');
            dialog.close();
        }

        // Close modal dialog on backdrop click
        document.getElementById('slot-dialog').addEventListener('click', function(e) {
            if (e.target === this) {
                closeSlotDialog();
            }
        });

        function updateLifetimeStats() {
            if (!globalSlots || globalSlots.length === 0) {
                document.getElementById('stat-billable').innerText = '-';
                document.getElementById('stat-avg-focus').innerText = '-';
                document.getElementById('stat-days-tracked').innerText = '-';
                document.getElementById('hint-billable').innerHTML = '&nbsp;';
                document.getElementById('hint-avg-focus').innerHTML = '&nbsp;';
                document.getElementById('hint-days-tracked').innerHTML = '&nbsp;';
                return;
            }

            let sumFocus = 0;
            let countSlots = 0;
            let billableSlots = 0;
            let daysRun = 0;

            let labelBillable = 'Billable';
            let labelFocus = 'Avg Focus';
            let labelDays = 'Days Run';
            
            let relevantDays = [];
            
            if (currentViewMode === 'daily') {
                if (daysMap[currentDateKey]) relevantDays.push(daysMap[currentDateKey]);
                labelBillable = 'Billable Today';
                labelFocus = 'Focus Today';
                labelDays = 'Logged Slots';
            } else if (currentViewMode === 'weekly') {
                const start = getStartOfWeek(currentDateKey);
                for (let i = 0; i < 7; i++) {
                    const d = new Date(start);
                    d.setDate(d.getDate() + i);
                    const y = d.getFullYear();
                    const m = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    const key = `${y}-${m}-${day}`;
                    if (daysMap[key]) relevantDays.push(daysMap[key]);
                }
                labelBillable = 'Billable This Week';
                labelFocus = 'Focus This Week';
                labelDays = 'Active Days';
            } else if (currentViewMode === 'monthly') {
                const parts = currentDateKey.split('-');
                const y = parts[0];
                const m = parts[1];
                for (let d = 1; d <= 31; d++) {
                    const key = `${y}-${m}-${String(d).padStart(2, '0')}`;
                    if (daysMap[key]) relevantDays.push(daysMap[key]);
                }
                labelBillable = 'Billable This Month';
                labelFocus = 'Focus This Month';
                labelDays = 'Active Days';
            }
            
            relevantDays.forEach(day => {
                let dayHasSlots = false;
                day.slots.forEach(slot => {
                    // Logged slot: at least one productive minute (focus_score > 0).
                    if (slot.focus_score > 0) {
                        sumFocus += slot.focus_score;
                        countSlots += 1;
                        dayHasSlots = true;
                        // Billable slot: cleared the focus gate (>= 40, ADR 0012).
                        // Same rule as the fat client's billable hero.
                        if (slot.focus_score >= 40) billableSlots += 1;
                    }
                });
                if (dayHasSlots) daysRun += 1;
            });

            const avgFocus = countSlots > 0 ? Math.round(sumFocus / countSlots) : 0;
            // Hero metric = billable time, identical rule to the fat client:
            // billable slots (focus >= 40) x 10 minutes.
            const billableMins = billableSlots * 10;
            const bHours = Math.floor(billableMins / 60);
            const bMins = billableMins % 60;

            document.getElementById('stat-billable').innerText = billableMins > 0 ? (bHours > 0 ? `${bHours}h ${bMins}m` : `${bMins}m`) : (countSlots > 0 ? '0m' : '-');
            document.getElementById('stat-avg-focus').innerText = countSlots > 0 ? `${avgFocus}%` : '-';
            document.getElementById('stat-days-tracked').innerText = currentViewMode === 'daily' ? (countSlots > 0 ? countSlots : '-') : (daysRun > 0 ? daysRun : '-');

            document.getElementById('label-billable').innerText = labelBillable;
            document.getElementById('label-avg-focus').innerText = labelFocus;
            document.getElementById('label-days-tracked').innerText = labelDays;

            // Make the slot basis explicit. The billable hero's sub-line reports the
            // logged-slot count (matching the fat client's "N slots logged today");
            // focus averages over those same logged slots.
            const slotWord = countSlots === 1 ? 'slot' : 'slots';
            document.getElementById('hint-billable').innerHTML =
                countSlots > 0 ? `${countSlots} ${slotWord} logged` : '&nbsp;';
            document.getElementById('hint-avg-focus').innerHTML =
                countSlots > 0 ? `over ${countSlots} logged ${slotWord}` : '&nbsp;';
            // Daily: the value already IS the slot count, so clarify each is 10 min.
            // Weekly/monthly: the value is days, so annotate the total logged slots.
            document.getElementById('hint-days-tracked').innerHTML = currentViewMode === 'daily'
                ? (countSlots > 0 ? '10 min each' : '&nbsp;')
                : (countSlots > 0 ? `${countSlots} logged ${slotWord}` : '&nbsp;');
        }

        function renderCurrentView() {
            if (currentViewMode === 'daily') {
                renderDayView();
            } else if (currentViewMode === 'weekly') {
                renderWeeklyView();
            } else if (currentViewMode === 'monthly') {
                renderMonthlyView();
            }
        }

        function renderDayView() {
            const container = document.getElementById('day-view-container');
            const datePicker = document.getElementById('date-picker');
            datePicker.value = currentDateKey;

            const prevBtn = document.getElementById('prev-day-btn');
            const nextBtn = document.getElementById('next-day-btn');

            updateLifetimeStats();

            const day = daysMap[currentDateKey];
            
            // If there's no data for the day, render an empty/offline state
            if (!day || day.slots.length === 0) {
                renderEmptyDayView(currentDateKey);
                return;
            }

            let daySumFocus = 0;
            let dayCountSlots = 0;
            day.slots.forEach(slot => {
                // Logged slot: at least one productive minute (focus_score > 0).
                if (slot.focus_score > 0) {
                    daySumFocus += slot.focus_score;
                    dayCountSlots += 1;
                }
            });

            const avgFocus = dayCountSlots > 0 ? Math.round(daySumFocus / dayCountSlots) : 0;
            const activeMins = day.totalLoggedSlots * 10;
            const hours = Math.floor(activeMins / 60);
            const mins = activeMins % 60;
            const activeTimeStr = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
            
            let focusColorClass = 'red';
            if (avgFocus >= 80) focusColorClass = 'green';
            else if (avgFocus >= 40) focusColorClass = 'yellow';

            const dayParts = currentDateKey.split('-');
            const dayStart = new Date(dayParts[0], dayParts[1] - 1, dayParts[2]);
            dayStart.setHours(0, 0, 0, 0);
            const dayStartSecs = Math.floor(dayStart.getTime() / 1000);

            // Render Hourly Heatmap row (24 columns)
            const heatmapCells = Array(24).fill(null).map((_, hour) => {
                const ampm = hour >= 12 ? 'PM' : 'AM';
                const displayHour = hour % 12 === 0 ? 12 : hour % 12;
                const hourStr = `${displayHour} ${ampm}`;
                
                let sliversHtml = '';
                let activeCount = 0;
                let sumScore = 0;
                let isPending = false;
                let hasAnySlot = false;

                for (let c = 0; c < 6; c++) {
                    const targetStart = dayStartSecs + (hour * 3600) + (c * 600);
                    const slot = day.slots.find(s => s.slot_start === targetStart);

                    if (!slot) {
                        sliversHtml += `<div style="flex:1; border-radius:1px; background: rgba(255,255,255,0.06);"></div>`;
                    } else if (slot.is_pending) {
                        isPending = true;
                        hasAnySlot = true;
                        sliversHtml += `<div style="flex:1; border-radius:1px; opacity:0.6; background: repeating-linear-gradient(-45deg, rgba(255,255,255,0.1), rgba(255,255,255,0.1) 2px, transparent 2px, transparent 4px);"></div>`;
                    } else {
                        hasAnySlot = true;
                        activeCount++;
                        sumScore += slot.focus_score;
                        let bgColor = 'var(--accent-red)';
                        if (slot.focus_score >= 80) bgColor = 'var(--accent-green)';
                        else if (slot.focus_score >= 40) bgColor = 'var(--accent-yellow)';
                        sliversHtml += `<div style="flex:1; border-radius:1px; background: ${bgColor};"></div>`;
                    }
                }
                
                let tooltipStr = `${hourStr} - Offline`;
                if (activeCount > 0) {
                    const avgScore = Math.round(sumScore / activeCount);
                    tooltipStr = `${hourStr} - Avg Focus: ${avgScore}%`;
                } else if (isPending) {
                    tooltipStr = `${hourStr} - Ongoing`;
                } else if (hasAnySlot) {
                    tooltipStr = `${hourStr} - Idle`;
                }
                
                return `<div class="heatmap-cell" onclick="document.getElementById('hour-row-${currentDateKey}-${hour}').scrollIntoView({behavior: 'smooth'})" style="cursor:pointer; display:flex; gap:2px; padding:3px;" data-tooltip="${tooltipStr}">
                    ${sliversHtml}
                </div>`;
            }).join('');

            let hourRowsHtml = '';
            for (let h = 0; h < 24; h++) {
                const ampm = h >= 12 ? 'PM' : 'AM';
                const displayHour = h % 12 === 0 ? 12 : h % 12;
                const hourLabelStr = `${String(displayHour).padStart(2, '0')}:00 ${ampm}`;
                
                let slotsInHourHtml = '';

                for (let c = 0; c < 6; c++) {
                    const targetStart = dayStartSecs + (h * 3600) + (c * 600);
                    const slot = day.slots.find(s => s.slot_start === targetStart);

                    if (slot) {
                        if (slot.is_pending) {
                            slotsInHourHtml += `
                                <div class="slot-card compact-card" style="opacity: 0.6; border-style: dashed; animation: pulse 2s infinite;">
                                    <div class="slot-compact-header">
                                        <span class="slot-compact-min">:${c * 10}</span>
                                        <span class="slot-compact-score" style="color: var(--text-muted);">...</span>
                                    </div>
                                    <div style="flex-grow: 1; display: flex; align-items: center; justify-content: center;">
                                        <span class="offline-text" style="color: var(--text-primary);">Evaluating...</span>
                                    </div>
                                </div>
                            `;
                        } else {
                            const slotScore = slot.focus_score;
                            let slotColorClass = 'red';
                            if (slotScore >= 80) slotColorClass = 'green';
                            else if (slotScore >= 40) slotColorClass = 'yellow';

                            const categoriesTooltip = Object.entries(slot.app_categories || {})
                                .map(([cat, count]) => `${cat}: ${count}m`)
                                .join(', ') || 'No apps logged';
                                
                            const categoriesList = Object.entries(slot.app_categories || {})
                                .sort((a, b) => b[1] - a[1])
                                .map(([cat, count]) => `<span style="background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:4px;">${cat}: ${count}m</span>`)
                                .join('');

                            let statsHtml = categoriesList 
                                ? `<div style="font-size: 0.75rem; color: var(--text-muted); display:flex; flex-direction:column; align-items:flex-start; gap:4px; margin-top:2px;">${categoriesList}</div>` 
                                : `<span style="color:var(--text-muted); font-size: 0.75rem;">No apps logged</span>`;
                            
                            let isDistracted = false;

                            if (slotScore === 0 && !(slot.total_keystrokes === 0 && slot.total_clicks === 0)) {
                                isDistracted = true;
                            }
                            
                            let extraClasses = isDistracted ? ' distracted-card' : '';

                            slotsInHourHtml += `
                                <div class="slot-card compact-card ${slotColorClass}${extraClasses}" title="${categoriesTooltip}">
                                    <div class="slot-compact-header">
                                        <span class="slot-compact-min">:${c * 10}</span>
                                        <span class="slot-compact-score ${slotColorClass}">${slotScore}%</span>
                                    </div>
                                    <div class="slot-compact-stats">
                                        ${statsHtml}
                                    </div>
                                    <button class="view-slot-compact-btn" onclick="showSlotDetails(${slot.slot_start}, event)">
                                        📋 Details
                                    </button>
                                </div>
                            `;
                        }
                    } else {
                        slotsInHourHtml += `
                            <div class="slot-card compact-card offline-card">
                                <div class="slot-compact-header">
                                    <span class="slot-compact-min">:${c * 10}</span>
                                    <span class="slot-compact-score" style="color: var(--text-muted);">Offline</span>
                                </div>
                                <div class="slot-compact-stats">
                                    <span>-</span>
                                    <span>-</span>
                                </div>
                                <span class="offline-text">No Telemetry</span>
                            </div>
                        `;
                    }
                }

                hourRowsHtml += `
                    <div class="hour-row" id="hour-row-${currentDateKey}-${h}">
                        <div class="hour-label">${hourLabelStr}</div>
                        ${slotsInHourHtml}
                    </div>
                `;
            }

            container.innerHTML = `
                <div class="day-view-header-detail">
                    <div class="day-view-title-group">
                        <span class="day-view-title">${day.formattedDate}</span>
                        <span class="day-view-meta">Productivity stats compiled locally and encrypted.</span>
                    </div>
                    <div class="day-view-badges">
                        <span class="badge badge-focus ${focusColorClass}" style="font-size:0.85rem; padding: 0.35rem 0.75rem;">${avgFocus}% Focus</span>
                        <span class="badge badge-time" style="font-size:0.85rem; padding: 0.35rem 0.75rem;">${activeTimeStr} Active (${day.totalLoggedSlots} ${day.totalLoggedSlots === 1 ? 'slot' : 'slots'})</span>
                    </div>
                </div>

                <div style="margin-bottom: 2rem; background: rgba(0,0,0,0.15); border: 1px solid var(--border-card); border-radius: 12px; padding: 1.2rem;">
                    <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.8px; margin-bottom: 0.6rem;">24-Hour Focus Heatmap</h4>
                    <div class="heatmap-bar">
                        ${heatmapCells}
                    </div>
                    <div class="heatmap-labels">
                        <span>12 AM</span>
                        <span>6 AM</span>
                        <span>12 PM</span>
                        <span>6 PM</span>
                        <span>11 PM</span>
                    </div>
                </div>

                <div class="day-grid-container">
                    <div class="hour-row grid-headers" style="position: sticky; top: 90px; z-index: 15; background: rgba(15, 17, 26, 0.85); backdrop-filter: blur(12px); padding: 0.5rem; border-radius: 8px; margin: -0.5rem -0.5rem 0.5rem -0.5rem; border-bottom: 1px solid var(--border-card);">
                        <div class="hour-label-header">Hour</div>
                        <div class="col-header">:00</div>
                        <div class="col-header">:10</div>
                        <div class="col-header">:20</div>
                        <div class="col-header">:30</div>
                        <div class="col-header">:40</div>
                        <div class="col-header">:50</div>
                    </div>
                    ${hourRowsHtml}
                </div>
            `;
        }
        
        function getStartOfWeek(dateStr) {
            const dateParts = dateStr.split('-');
            const d = new Date(parseInt(dateParts[0]), parseInt(dateParts[1]) - 1, parseInt(dateParts[2]));
            const day = d.getDay();
            const diff = d.getDate() - day + (day === 0 && weekStartDay === 1 ? -6 : weekStartDay);
            const startOfWeek = new Date(d.setDate(diff));
            return startOfWeek;
        }

        function renderWeeklyView() {
            const container = document.getElementById('week-view-container');
            
            const startOfWeek = getStartOfWeek(currentDateKey);
            const startYear = startOfWeek.getFullYear();
            const startMonth = String(startOfWeek.getMonth() + 1).padStart(2, '0');
            const startDay = String(startOfWeek.getDate()).padStart(2, '0');
            const newDateKey = `${startYear}-${startMonth}-${startDay}`;
            
            if (currentDateKey !== newDateKey) {
                currentDateKey = newDateKey;
                updateUrl();
            }

            updateLifetimeStats();
            document.getElementById('date-picker').value = currentDateKey;
            const endOfWeek = new Date(startOfWeek);
            endOfWeek.setDate(endOfWeek.getDate() + 6);
            
            const startStr = startOfWeek.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            const endStr = endOfWeek.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            
            let html = `
                <div class="day-view-header-detail">
                    <div class="day-view-title-group">
                        <span class="day-view-title">Week of ${startStr} - ${endStr}</span>
                        <span class="day-view-meta">Weekly aggregate productivity overview.</span>
                    </div>
                </div>
                <div class="month-grid" style="margin-top: 0;">
            `;

            const weekNamesHTML = [];
            for (let i = 0; i < 7; i++) {
                const cur = new Date(startOfWeek);
                cur.setDate(cur.getDate() + i);
                weekNamesHTML.push(`<div class="week-day-header">${cur.toLocaleDateString('en-US', { weekday: 'short' })}</div>`);
            }
            html += weekNamesHTML.join('');
            
            const daysHTML = [];
            for (let i = 0; i < 7; i++) {
                const cur = new Date(startOfWeek);
                cur.setDate(cur.getDate() + i);
                const y = cur.getFullYear();
                const m = String(cur.getMonth() + 1).padStart(2, '0');
                const d = String(cur.getDate()).padStart(2, '0');
                const dKey = `${y}-${m}-${d}`;
                
                const dayName = cur.toLocaleDateString('en-US', { weekday: 'short' });
                daysHTML.push(renderDayCell(dKey, dayName, d));
            }

            html += daysHTML.join('') + `</div>`;
            container.innerHTML = html;
        }

        function renderMonthlyView() {
            const container = document.getElementById('month-view-container');
            
            const curDateParts = currentDateKey.split('-');
            const newDateKey = `${curDateParts[0]}-${curDateParts[1]}-01`;
            
            if (currentDateKey !== newDateKey) {
                currentDateKey = newDateKey;
                updateUrl();
            }

            updateLifetimeStats();
            
            const dateParts = currentDateKey.split('-');
            document.getElementById('date-picker').value = `${dateParts[0]}-${dateParts[1]}`;

            const year = parseInt(dateParts[0], 10);
            const month = parseInt(dateParts[1], 10) - 1;
            
            const firstDayOfMonth = new Date(year, month, 1);
            const lastDayOfMonth = new Date(year, month + 1, 0);
            
            const monthStr = firstDayOfMonth.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
            
            let html = `
                <div class="day-view-header-detail">
                    <div class="day-view-title-group">
                        <span class="day-view-title">${monthStr}</span>
                        <span class="day-view-meta">Monthly aggregate productivity overview.</span>
                    </div>
                </div>
                <div class="month-grid" style="margin-top: 0;">
            `;
            
            const weekNamesHTML = [];
            // generate 7 days from an arbitrary start date that matches weekStartDay
            // 2023-01-01 is a Sunday (0), 2023-01-02 is Monday (1)
            for (let i = 0; i < 7; i++) {
                const cur = new Date(2023, 0, 1 + weekStartDay + i);
                weekNamesHTML.push(`<div class="week-day-header">${cur.toLocaleDateString('en-US', { weekday: 'short' })}</div>`);
            }
            html += weekNamesHTML.join('');
            
            const firstDayOfWeek = firstDayOfMonth.getDay();
            let emptyCells = firstDayOfWeek - weekStartDay;
            if (emptyCells < 0) emptyCells += 7;
            
            for (let i = 0; i < emptyCells; i++) {
                html += `<div></div>`;
            }
            
            for (let d = 1; d <= lastDayOfMonth.getDate(); d++) {
                const cur = new Date(year, month, d);
                const y = cur.getFullYear();
                const mStr = String(cur.getMonth() + 1).padStart(2, '0');
                const dStr = String(cur.getDate()).padStart(2, '0');
                const dKey = `${y}-${mStr}-${dStr}`;
                
                html += renderDayCell(dKey, '', d);
            }
            
            html += `</div>`;
            container.innerHTML = html;
        }

        function renderDayCell(dateKey, headerText, dayNum) {
            const dayData = daysMap[dateKey];
            let avgFocus = 0;
            let activeTimeStr = '0m';
            let colorClass = '';
            
            if (dayData && dayData.totalLoggedSlots > 0) {
                let daySumFocus = 0;
                let dayCountSlots = 0;
                dayData.slots.forEach(slot => {
                    // Logged slot: at least one productive minute (focus_score > 0).
                    if (slot.focus_score > 0) {
                        daySumFocus += slot.focus_score;
                        dayCountSlots += 1;
                    }
                });

                avgFocus = dayCountSlots > 0 ? Math.round(daySumFocus / dayCountSlots) : 0;
                const activeMins = dayData.totalLoggedSlots * 10;
                const hours = Math.floor(activeMins / 60);
                const mins = activeMins % 60;
                activeTimeStr = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
                
                if (avgFocus >= 80) colorClass = 'green';
                else if (avgFocus >= 40) colorClass = 'yellow';
                else colorClass = 'red';
            }
            
            return `
                <div class="month-day-cell ${colorClass}" onclick="switchView('daily'); navigateToDate('${dateKey}');">
                    <div class="month-day-header">
                        <span>${headerText}</span>
                        <span style="color: var(--text-main);">${dayNum}</span>
                    </div>
                    <div class="month-day-stats">
                        ${dayData && dayData.totalLoggedSlots > 0 ? `
                            <span style="color: var(--accent-${colorClass === 'green' ? 'green' : (colorClass === 'yellow' ? 'yellow' : 'red')}); font-weight: 800; font-size: 0.9rem;">${avgFocus}%</span>
                            <span>${activeTimeStr}</span>
                        ` : `<span style="color: var(--text-muted); padding-top: 0.5rem; font-size: 0.7rem;">No data</span>`}
                    </div>
                </div>
            `;
        }

        function renderEmptyDayView(dateKey) {
            const container = document.getElementById('day-view-container');
            const formattedDate = getFormattedDate(dateKey);

            // Empty heatmap cells
            const heatmapCells = Array(24).fill(null).map((_, hour) => {
                const ampm = hour >= 12 ? 'PM' : 'AM';
                const displayHour = hour % 12 === 0 ? 12 : hour % 12;
                let slivers = '';
                for (let i = 0; i < 6; i++) {
                    slivers += `<div style="flex:1; border-radius:1px; background: rgba(255,255,255,0.06);"></div>`;
                }
                return `<div class="heatmap-cell" style="display:flex; gap:2px; padding:3px;" data-tooltip="${displayHour} ${ampm} - Offline">${slivers}</div>`;
            }).join('');

            // 24 offline rows
            let hourRowsHtml = '';
            for (let h = 0; h < 24; h++) {
                const ampm = h >= 12 ? 'PM' : 'AM';
                const displayHour = h % 12 === 0 ? 12 : h % 12;
                const hourLabelStr = `${String(displayHour).padStart(2, '0')}:00 ${ampm}`;
                
                let slotsInHourHtml = '';
                for (let c = 0; c < 6; c++) {
                    slotsInHourHtml += `
                        <div class="slot-card compact-card offline-card">
                            <div class="slot-compact-header">
                                <span class="slot-compact-min">:${c * 10}</span>
                                <span class="slot-compact-score" style="color: var(--text-muted);">Offline</span>
                            </div>
                            <div class="slot-compact-stats">
                                <span>-</span>
                                <span>-</span>
                            </div>
                            <span class="offline-text">No Telemetry</span>
                        </div>
                    `;
                }

                hourRowsHtml += `
                    <div class="hour-row">
                        <div class="hour-label">${hourLabelStr}</div>
                        ${slotsInHourHtml}
                    </div>
                `;
            }

            container.innerHTML = `
                <div class="day-view-header-detail">
                    <div class="day-view-title-group">
                        <span class="day-view-title">${formattedDate}</span>
                        <span class="day-view-meta">No activity data logged for this date.</span>
                    </div>
                    <div class="day-view-badges">
                        <span class="badge" style="font-size:0.85rem; padding: 0.35rem 0.75rem; background: rgba(255,255,255,0.02); color: var(--text-muted);">0% Focus</span>
                        <span class="badge badge-time" style="font-size:0.85rem; padding: 0.35rem 0.75rem; background: rgba(255,255,255,0.02); color: var(--text-muted);">0m Active</span>
                    </div>
                </div>

                <div style="margin-bottom: 2rem; background: rgba(0,0,0,0.15); border: 1px solid var(--border-card); border-radius: 12px; padding: 1.2rem;">
                    <h4 style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.8px; margin-bottom: 0.6rem;">24-Hour Focus Heatmap</h4>
                    <div class="heatmap-bar">
                        ${heatmapCells}
                    </div>
                    <div class="heatmap-labels">
                        <span>12 AM</span>
                        <span>6 AM</span>
                        <span>12 PM</span>
                        <span>6 PM</span>
                        <span>11 PM</span>
                    </div>
                </div>

                <div class="day-grid-container">
                    <div class="hour-row grid-headers" style="position: sticky; top: 90px; z-index: 15; background: rgba(15, 17, 26, 0.85); backdrop-filter: blur(12px); padding: 0.5rem; border-radius: 8px; margin: -0.5rem -0.5rem 0.5rem -0.5rem; border-bottom: 1px solid var(--border-card);">
                        <div class="hour-label-header">Hour</div>
                        <div class="col-header">:00</div>
                        <div class="col-header">:10</div>
                        <div class="col-header">:20</div>
                        <div class="col-header">:30</div>
                        <div class="col-header">:40</div>
                        <div class="col-header">:50</div>
                    </div>
                    ${hourRowsHtml}
                </div>
            `;
        }

        // Export CSV logic
        function openExportModal() { document.getElementById('export-dialog').showModal(); }
        function closeExportModal() { document.getElementById('export-dialog').close(); }

        async function exportCsv() {
            const btn = document.getElementById('export-btn');
            const range = document.getElementById('export-range').value;
            let start = null;
            let end = null;
            if (range === 'custom') {
                const startVal = document.getElementById('export-start').value;
                const endVal = document.getElementById('export-end').value;
                if (!startVal || !endVal) {
                    alert('Please select both start and end dates.');
                    return;
                }
                start = Math.floor(new Date(startVal).getTime() / 1000);
                // Add 86400 to include the entire end day
                end = Math.floor(new Date(endVal).getTime() / 1000) + 86400;
            }

            const originalText = btn.innerHTML;
            btn.innerHTML = '<span>Exporting...</span>';
            btn.disabled = true;
            try {
                // Rust builds the CSV, opens a native save dialog, and writes the
                // file. Returns the saved path, or null if the user cancelled.
                const savedPath = await invoke('export_dashboard_csv', { range, start, end });
                if (savedPath) {
                    closeExportModal();
                }
            } catch (error) {
                alert('Failed to export CSV: ' + error);
            } finally {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        }



        // When embedded in the app window (iframe), add a Back control to the
        // header that returns to the metrics home. Standalone, this is skipped.
        if (window.parent && window.parent !== window) {
            const header = document.querySelector('header');
            const logoSection = header && header.querySelector('.logo-section');
            if (logoSection) {
                const back = document.createElement('button');
                back.className = 'nav-btn';
                back.id = 'back-to-home-btn';
                back.type = 'button';
                back.textContent = '← Back';
                back.title = 'Back to overview';
                back.addEventListener('click', goHome);
                logoSection.insertBefore(back, logoSection.firstChild);
            }
        }

        // Initialize
        fetchDashboardData();
        // Poll database updates every 15 seconds
        setInterval(fetchDashboardData, 15000);
    