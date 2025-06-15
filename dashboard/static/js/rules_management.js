document.addEventListener("DOMContentLoaded", () => {
    // Existing rule management elements
    const rulesTable = document.getElementById("rulesTable");
    const ruleSearch = document.getElementById("ruleSearch");
    const categoryFilter = document.getElementById("categoryFilter");
    const applyChangesBtn = document.getElementById("applyChanges");
    const paginationTop = document.getElementById("paginationTop");
    const paginationBottom = document.getElementById("paginationBottom");

    // New rule creation elements
    const newRuleForm = document.getElementById("newRuleForm");
    const ruleTypeSelect = document.getElementById("ruleType");
    const targetContainer = document.getElementById("targetContainer");
    const patternContainer = document.getElementById("patternContainer");
    const customRuleContainer = document.getElementById("customRuleContainer");
    const generatedRuleContainer = document.getElementById("generatedRuleContainer");
    const generatedRuleText = document.getElementById("generatedRuleText");
    const saveRuleBtn = document.getElementById("saveRuleBtn");

    let rules = [];
    const changedRules = new Map();

    const rowsPerPage = 10;
    let currentPage = 1;
    let filteredRules = [];

    // Column filter values
    const columnFilters = {
        rule_id: '',
        description: '',
        category: '',
        severity: '',
        current_action: ''
    };

    // Initialize the page
    async function init() {
        setupEventListeners();
        await loadRules();
    }

    function setupEventListeners() {
        // Existing rule management listeners
        ruleSearch.addEventListener("input", () => {
            currentPage = 1;
            renderRules();
        });

        categoryFilter.addEventListener("change", () => {
            currentPage = 1;
            renderRules();
        });

        applyChangesBtn.addEventListener("click", applyChanges);

        // New rule creation listeners
        ruleTypeSelect.addEventListener("change", handleRuleTypeChange);
        newRuleForm.addEventListener("submit", handleNewRuleSubmit);
        saveRuleBtn.addEventListener("click", saveCustomRule);

        // Column filter listeners
        document.querySelectorAll('.column-filter').forEach(input => {
            const column = input.dataset.column;
            input.addEventListener('input', () => {
                columnFilters[column] = input.value.toLowerCase();
                currentPage = 1;
                renderRules();
            });
        });
    }

    // Load existing rules from API
    async function loadRules() {
        try {
            const response = await fetch("/api/rules");
            if (!response.ok) throw new Error("Failed to fetch rules");
            rules = await response.json();
            currentPage = 1;
            renderRules();
        } catch (error) {
            showAlert("Error loading rules: " + error.message, "danger");
        }
    }

    // Render the rules table with pagination
    function renderRules() {
        const searchTerm = (ruleSearch.value || "").toLowerCase();
        const category = categoryFilter.value || "";

        filteredRules = rules.filter(rule => {
            // Apply main search (searches description and rule_id)
            const matchesSearch = searchTerm === '' ||
                (rule.description || "").toLowerCase().includes(searchTerm) ||
                (rule.rule_id || "").toLowerCase().includes(searchTerm);

            // Apply category filter
            const matchesCategory = category === "" ||
                (rule.category || "").toLowerCase() === category.toLowerCase();

            // Apply column filters
            const matchesColumnFilters = Object.entries(columnFilters).every(([column, filterValue]) => {
                if (!filterValue) return true; // No filter for this column

                const cellValue = String(rule[column] || "").toLowerCase();
                return cellValue.includes(filterValue);
            });

            return matchesSearch && matchesCategory && matchesColumnFilters;
        });

        if (filteredRules.length === 0) {
            rulesTable.innerHTML = `<tr><td colspan="6" class="text-center">No rules found</td></tr>`;
            paginationTop.innerHTML = "";
            paginationBottom.innerHTML = "";
            return;
        }

        const totalPages = Math.ceil(filteredRules.length / rowsPerPage);
        if (currentPage > totalPages) currentPage = totalPages;

        const startIndex = (currentPage - 1) * rowsPerPage;
        const endIndex = startIndex + rowsPerPage;
        const pageRules = filteredRules.slice(startIndex, endIndex);

        rulesTable.innerHTML = "";
        for (const rule of pageRules) {
            const currentAction = rule.current_action || "";
            const ruleId = rule.rule_id || "";

            const tr = document.createElement("tr");

            tr.innerHTML = `
                <td>${ruleId}</td>
                <td class="description-cell">${rule.description || ""}</td>
                <td>${rule.category || ""}</td>
                <td>${rule.severity || ""}</td>
                <td>${currentAction}</td>
                <td>
                    <select class="form-select change-action" data-rule-id="${ruleId}">
                      <option value="block" ${currentAction.toLowerCase() === "block" ? "selected" : ""}>Block</option>
                      <option value="monitor" ${currentAction.toLowerCase() === "monitor" ? "selected" : ""}>Monitor</option>
                      <option value="disabled" ${currentAction.toLowerCase() === "disabled" ? "selected" : ""}>Disabled</option>
                    </select>
                </td>
            `;
            rulesTable.appendChild(tr);
        }

        document.querySelectorAll(".change-action").forEach(select => {
            select.addEventListener("change", (e) => {
                const ruleId = e.target.dataset.ruleId;
                const newAction = e.target.value;
                changedRules.set(ruleId, newAction);
            });
        });

        renderPagination(totalPages);
    }

    // Handle pagination rendering
    function renderPagination(totalPages) {
        const createPageItem = (pageNum, text = null, disabled = false, active = false) => {
            const li = document.createElement("li");
            li.className = "page-item";
            if (disabled) li.classList.add("disabled");
            if (active) li.classList.add("active");

            const a = document.createElement("a");
            a.className = "page-link";
            a.href = "#";
            a.textContent = text || pageNum;
            a.addEventListener("click", (e) => {
                e.preventDefault();
                if (!disabled && currentPage !== pageNum) {
                    currentPage = pageNum;
                    renderRules();
                    window.scrollTo(0, 0);
                }
            });

            li.appendChild(a);
            return li;
        };

        paginationTop.innerHTML = "";
        paginationBottom.innerHTML = "";

        const buildCompactPagination = (container) => {
            container.appendChild(createPageItem(currentPage - 1, "Previous", currentPage === 1));

            const liInfo = document.createElement("li");
            liInfo.className = "page-item disabled";
            const spanInfo = document.createElement("span");
            spanInfo.className = "page-link";
            spanInfo.textContent = `${currentPage} of ${totalPages}`;
            liInfo.appendChild(spanInfo);
            container.appendChild(liInfo);

            container.appendChild(createPageItem(currentPage + 1, "Next", currentPage === totalPages));
        };

        buildCompactPagination(paginationTop);
        buildCompactPagination(paginationBottom);
    }

    // Apply changes to existing rules
    async function applyChanges() {
        if (changedRules.size === 0) {
            showAlert("No changes to apply.", "info");
            return;
        }

        const failedUpdates = [];

        for (const [ruleId, action] of changedRules.entries()) {
            try {
                const response = await fetch(`/api/rules/${ruleId}/action`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ action: action }),
                });

                if (!response.ok) {
                    const error = await response.json();
                    let errMsg = error.detail;
                    if (typeof errMsg === 'object') {
                        errMsg = JSON.stringify(errMsg);
                    }
                    console.error(`Failed to update rule ${ruleId}: ${errMsg}`);
                    failedUpdates.push(ruleId);
                }
            } catch (error) {
                console.error(`Exception updating rule ${ruleId}:`, error);
                failedUpdates.push(ruleId);
            }
        }

        if (failedUpdates.length > 0) {
            showAlert(`Some rules failed to update:\n${failedUpdates.join(", ")}`, "danger");
        } else {
            showAlert("All changes applied successfully!", "success");
        }

        changedRules.clear();
        await loadRules();
    }

    // New rule creation functions
    function handleRuleTypeChange() {
        const ruleType = this.value;

        targetContainer.style.display = 'none';
        patternContainer.style.display = 'none';
        customRuleContainer.style.display = 'none';

        if (ruleType === 'custom') {
            customRuleContainer.style.display = 'block';
        } else if (ruleType) {
            targetContainer.style.display = 'block';
            patternContainer.style.display = 'block';

            // Update labels based on rule type
            if (ruleType === 'header_block') {
                document.getElementById('targetLabel').textContent = 'Header Name';
                document.getElementById('patternLabel').textContent = 'Pattern to Match';
            } else if (ruleType === 'ip_block') {
                document.getElementById('targetLabel').textContent = 'IP Address';
                document.getElementById('patternLabel').textContent = 'IP Pattern';
            } else if (ruleType === 'user_agent_block') {
                document.getElementById('targetLabel').textContent = 'User Agent';
                document.getElementById('patternLabel').textContent = 'Pattern to Match';
            }
        }
    }

    function handleNewRuleSubmit(e) {
        e.preventDefault();
        generateRule();
    }

    function generateRule() {
        const ruleType = ruleTypeSelect.value;
        let ruleText = '';

        if (ruleType === 'custom') {
            ruleText = document.getElementById('customRuleText').value.trim();
            if (!ruleText) {
                showAlert('Please enter custom rule text', 'warning');
                return;
            }
        } else {
            const target = document.getElementById('ruleTarget').value.trim();
            const pattern = document.getElementById('rulePattern').value.trim();

            if (!target || !pattern) {
                showAlert('Please fill in all fields', 'warning');
                return;
            }

            // Generate new rule ID (simple implementation)
            const newRuleId = generateNewRuleId();

            // Generate rule based on type
            switch (ruleType) {
                case 'header_block':
                    ruleText = `SecRule REQUEST_HEADERS:${target} "${pattern}" \\\n` +
                        `    "id:${newRuleId},phase:1,deny,status:406,msg:'Custom rule - block ${target} header'"`;
                    break;

                case 'ip_block':
                    ruleText = `SecRule REMOTE_ADDR "${pattern}" \\\n` +
                        `    "id:${newRuleId},phase:1,deny,status:406,msg:'Custom rule - block IP ${pattern}'"`;
                    break;

                case 'user_agent_block':
                    ruleText = `SecRule REQUEST_HEADERS:User-Agent "${pattern}" \\\n` +
                        `    "id:${newRuleId},phase:1,deny,status:406,msg:'Custom rule - block User-Agent ${pattern}'"`;
                    break;
            }
        }

        generatedRuleText.textContent = ruleText;
        generatedRuleContainer.style.display = 'block';
    }

    function generateNewRuleId() {
        // Generate a new rule ID in the custom range (10010000-10019999)
        const min = 10010000;
        const max = 10019999;
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    async function saveCustomRule() {
        const ruleText = generatedRuleText.textContent;

        if (!ruleText) {
            showAlert('No rule to save', 'warning');
            return;
        }

        try {
            const response = await fetch('/rules/custom', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    rule_text: ruleText,
                    filename: 'custom_rules4.conf'
                })
            });

            if (response.ok) {
                showAlert('Rule saved successfully!', 'success');
                generatedRuleContainer.style.display = 'none';
                newRuleForm.reset();
                // Refresh the rules list
                await loadRules();
            } else {
                throw new Error('Failed to save rule');
            }
        } catch (error) {
            showAlert('Error saving rule: ' + error.message, 'danger');
        }
    }

    // Helper function to show alerts
    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;

        // Create a temporary container for alerts
        const alertContainer = document.getElementById('alertContainer') || createAlertContainer();
        alertContainer.prepend(alertDiv);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }, 5000);
    }

    function createAlertContainer() {
        const container = document.createElement('div');
        container.id = 'alertContainer';
        container.style.position = 'fixed';
        container.style.top = '20px';
        container.style.right = '20px';
        container.style.zIndex = '1000';
        container.style.width = '350px';
        document.body.appendChild(container);
        return container;
    }

    // Initialize the application
    init();
});