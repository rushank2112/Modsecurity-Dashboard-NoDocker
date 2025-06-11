document.addEventListener("DOMContentLoaded", () => {
    const rulesTable = document.getElementById("rulesTable");
    const ruleSearch = document.getElementById("ruleSearch");
    const categoryFilter = document.getElementById("categoryFilter");
    const applyChangesBtn = document.getElementById("applyChanges");
    const paginationTop = document.getElementById("paginationTop");
    const paginationBottom = document.getElementById("paginationBottom");

    let rules = [];
    const changedRules = new Map();

    const rowsPerPage = 10;
    let currentPage = 1;
    let filteredRules = [];

    async function loadRules() {
        try {
            const response = await fetch("/api/rules");
            if (!response.ok) throw new Error("Failed to fetch rules");
            rules = await response.json();
            currentPage = 1;
            renderRules();
        } catch (error) {
            alert("Error loading rules: " + error.message);
        }
    }

    function renderRules() {
        const searchTerm = (ruleSearch.value || "").toLowerCase();
        const category = categoryFilter.value || "";

        filteredRules = rules.filter(rule => {
            const description = (rule.description || "").toLowerCase();
            const ruleId = rule.rule_id || "";
            const categoryValue = rule.category || "";

            const matchesSearch =
                description.includes(searchTerm) ||
                ruleId.includes(searchTerm);
            const matchesCategory = category === "" || categoryValue === category;
            return matchesSearch && matchesCategory;
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

    async function applyChanges() {
        if (changedRules.size === 0) {
            alert("No changes to apply.");
            return;
        }

        const failedUpdates = [];

        for (const [ruleId, action] of changedRules.entries()) {
            try {
                // Send the action directly, no mapping needed
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
                    console.error(`❌ Failed to update rule ${ruleId}: ${errMsg}`);
                    failedUpdates.push(ruleId);
                }
            } catch (error) {
                console.error(`❌ Exception updating rule ${ruleId}:`, error);
                failedUpdates.push(ruleId);
            }
        }

        if (failedUpdates.length > 0) {
            alert(`Some rules failed to update:\n${failedUpdates.join(", ")}`);
        } else {
            alert("✅ All changes applied successfully!");
        }

        changedRules.clear();
        await loadRules();
    }

    ruleSearch.addEventListener("input", () => {
        currentPage = 1;
        renderRules();
    });

    categoryFilter.addEventListener("change", () => {
        currentPage = 1;
        renderRules();
    });

    applyChangesBtn.addEventListener("click", applyChanges);

    loadRules();
});
