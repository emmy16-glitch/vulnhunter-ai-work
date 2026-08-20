(() => {
  "use strict";

  if (typeof window === "undefined" || typeof document === "undefined") return;

  const STORAGE_PREFIX = "vh-security-table:";
  const PAGE_SIZES = [10, 25, 50, 100];
  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const escapeKey = (value) => text(value).replace(/[^a-zA-Z0-9:_-]/g, "_");
  const isField = (element) => element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement;

  const readJson = (key, fallback) => {
    try {
      const value = JSON.parse(window.localStorage.getItem(key) || "null");
      return value && typeof value === "object" ? value : fallback;
    } catch (_error) {
      return fallback;
    }
  };

  const saveJson = (key, value) => {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (_error) {
      // UI preferences are optional and must never block a security workflow.
    }
  };

  const labelize = (value) => text(value).replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

  const setIndeterminate = (checkbox, value) => {
    if (checkbox) checkbox.indeterminate = Boolean(value);
  };

  const dispatch = (name, detail) => {
    document.dispatchEvent(new CustomEvent(name, { detail }));
  };

  class SecurityTable {
    constructor(root, config = {}) {
      this.root = root;
      this.config = config;
      this.tableKey = escapeKey(config.tableKey || root.dataset.securityTable || "default");
      this.rows = Array.isArray(config.rows) ? config.rows.slice() : [];
      this.columns = Array.isArray(config.columns) ? config.columns.map((column) => ({ ...column, id: column.id || column.key })) : [];
      this.getRowId = config.getRowId || ((row, index) => text(row.id || row.record_id || row.evidence_id || row.seed_id || row.node_id || index));
      this.selectedIds = new Set(config.selectedIds || []);
      this.expandedId = null;
      this.page = 1;
      this.preferences = {
        pageSize: 25,
        visibleColumns: null,
        sortId: null,
        sortDirection: "asc",
        view: "all",
        ...(readJson(`${STORAGE_PREFIX}${this.tableKey}`, {}) || {}),
      };
      this.pageSize = PAGE_SIZES.includes(Number(this.preferences.pageSize)) ? Number(this.preferences.pageSize) : 25;
      this.search = "";
      this.filters = {};
      this.refs = {};
    }

    mount() {
      this.root.replaceChildren();
      this.root.classList.add("vh-security-table-root");
      this.renderToolbar();
      this.renderTableShell();
      this.render();
      this.bindKeyboardShortcuts();
      return this;
    }

    persistPreferences() {
      saveJson(`${STORAGE_PREFIX}${this.tableKey}`, {
        pageSize: this.pageSize,
        visibleColumns: this.visibleColumnIds(),
        sortId: this.preferences.sortId,
        sortDirection: this.preferences.sortDirection,
        view: this.preferences.view,
      });
    }

    visibleColumnIds() {
      const configured = this.config.columns || [];
      if (Array.isArray(this.preferences.visibleColumns) && this.preferences.visibleColumns.length) {
        const allowed = new Set(configured.map((column) => column.id));
        return this.preferences.visibleColumns.filter((id) => allowed.has(id));
      }
      return configured.filter((column) => column.visibleByDefault !== false).map((column) => column.id);
    }

    visibleColumns() {
      const visible = new Set(this.visibleColumnIds());
      return this.columns.filter((column) => visible.has(column.id));
    }

    renderToolbar() {
      const toolbar = document.createElement("div");
      toolbar.className = "vh-security-table-toolbar";
      const heading = document.createElement("div");
      heading.className = "vh-security-table-heading";
      const title = document.createElement("h3");
      title.textContent = this.config.title || "Security records";
      const description = document.createElement("p");
      description.textContent = this.config.description || "Persisted records from the selected assessment.";
      heading.append(title, description);

      const controls = document.createElement("div");
      controls.className = "vh-security-table-controls";
      const search = document.createElement("input");
      search.type = "search";
      search.className = "vh-security-table-search";
      search.placeholder = this.config.searchPlaceholder || `Search ${text(this.config.title || "records").toLowerCase()}…`;
      search.setAttribute("aria-label", search.placeholder);
      search.addEventListener("input", () => {
        this.search = search.value.trim().toLowerCase();
        this.page = 1;
        this.render();
      });
      this.refs.search = search;
      controls.append(search);

      const filters = Array.isArray(this.config.filters) ? this.config.filters : [];
      filters.slice(0, 3).forEach((filter) => {
        const select = document.createElement("select");
        select.className = "vh-security-table-filter";
        select.dataset.filterId = filter.id;
        select.setAttribute("aria-label", filter.label);
        (filter.options || []).forEach((option) => {
          const item = document.createElement("option");
          item.value = text(option.value);
          item.textContent = text(option.label || labelize(option.value));
          select.append(item);
        });
        select.addEventListener("change", () => {
          this.filters[filter.id] = select.value;
          this.page = 1;
          this.render();
        });
        controls.append(select);
      });

      const columnsButton = document.createElement("button");
      columnsButton.type = "button";
      columnsButton.className = "vh-button-secondary vh-security-table-columns-button";
      columnsButton.textContent = "Columns";
      columnsButton.setAttribute("aria-expanded", "false");
      columnsButton.addEventListener("click", () => this.toggleColumnMenu(columnsButton));
      controls.append(columnsButton);
      this.refs.columnsButton = columnsButton;
      this.root.append(toolbar);
      this.refs.toolbar = toolbar;

      const views = Array.isArray(this.config.views || this.config.savedViews) ? (this.config.views || this.config.savedViews) : [];
      if (views.length) {
        const viewSelect = document.createElement("select");
        viewSelect.className = "vh-security-table-view-selector";
        viewSelect.setAttribute("aria-label", "Saved security table view");
        views.forEach((view) => {
          const option = document.createElement("option");
          option.value = view.id;
          option.textContent = view.label;
          viewSelect.append(option);
        });
        viewSelect.value = views.some((view) => view.id === this.preferences.view) ? this.preferences.view : views[0].id;
        viewSelect.addEventListener("change", () => {
          this.preferences.view = viewSelect.value;
          this.page = 1;
          this.persistPreferences();
          this.render();
        });
        heading.append(viewSelect);
      }
      toolbar.prepend(heading);
    }

    toggleColumnMenu(button) {
      const existing = this.root.querySelector(".vh-security-table-column-menu");
      if (existing) {
        existing.remove();
        button.setAttribute("aria-expanded", "false");
        return;
      }
      const menu = document.createElement("div");
      menu.className = "vh-security-table-column-menu";
      menu.setAttribute("role", "menu");
      this.columns.forEach((column) => {
        const label = document.createElement("label");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = this.visibleColumnIds().includes(column.id);
        checkbox.disabled = column.critical === true;
        checkbox.setAttribute("aria-label", `Show ${column.label} column`);
        checkbox.addEventListener("change", () => {
          const ids = new Set(this.visibleColumnIds());
          if (checkbox.checked) ids.add(column.id);
          else ids.delete(column.id);
          this.preferences.visibleColumns = [...ids];
          this.persistPreferences();
          this.render();
        });
        label.append(checkbox, document.createTextNode(column.label));
        menu.append(label);
      });
      button.parentElement?.append(menu);
      button.setAttribute("aria-expanded", "true");
    }

    renderTableShell() {
      const selectedBar = document.createElement("div");
      selectedBar.className = "vh-security-table-bulk-bar";
      selectedBar.hidden = true;
      selectedBar.setAttribute("aria-live", "polite");
      const count = document.createElement("strong");
      const actionGroup = document.createElement("div");
      actionGroup.className = "vh-security-table-bulk-actions";
      selectedBar.append(count, actionGroup);
      this.refs.bulkBar = selectedBar;
      this.refs.bulkCount = count;
      this.refs.bulkActions = actionGroup;
      this.root.append(selectedBar);

      const tableWrap = document.createElement("div");
      tableWrap.className = "vh-security-table-wrap";
      const table = document.createElement("table");
      table.className = "vh-table vh-security-table";
      tableWrap.append(table);
      this.refs.tableWrap = tableWrap;
      this.refs.table = table;
      this.root.append(tableWrap);

      const cards = document.createElement("div");
      cards.className = "vh-security-table-cards";
      this.refs.cards = cards;
      this.root.append(cards);

      const footer = document.createElement("footer");
      footer.className = "vh-security-table-footer";
      this.refs.footer = footer;
      this.root.append(footer);
    }

    filteredRows() {
      let rows = this.rows.slice();
      const views = Array.isArray(this.config.views || this.config.savedViews) ? (this.config.views || this.config.savedViews) : [];
      const activeView = views.find((view) => view.id === this.preferences.view);
      if (activeView?.predicate) rows = rows.filter(activeView.predicate);
      rows = rows.filter((row) => {
        const haystack = this.columns.map((column) => text(column.value ? column.value(row) : row[column.id])).join(" ").toLowerCase();
        if (this.search && !haystack.includes(this.search)) return false;
        return Object.entries(this.filters).every(([key, value]) => !value || value === "all" || text(row[key]).toLowerCase() === text(value).toLowerCase());
      });
      const sortColumn = this.columns.find((column) => column.id === this.preferences.sortId);
      if (sortColumn) {
        const direction = this.preferences.sortDirection === "desc" ? -1 : 1;
        rows.sort((left, right) => text(sortColumn.value ? sortColumn.value(left) : left[sortColumn.id]).localeCompare(text(sortColumn.value ? sortColumn.value(right) : right[sortColumn.id]), undefined, { numeric: true }) * direction);
      }
      return rows;
    }

    render() {
      const rows = this.filteredRows();
      const totalPages = Math.max(1, Math.ceil(rows.length / this.pageSize));
      this.page = Math.min(this.page, totalPages);
      const start = (this.page - 1) * this.pageSize;
      const pageRows = rows.slice(start, start + this.pageSize);
      this.renderTable(pageRows, rows.length, totalPages);
      this.renderCards(pageRows);
      this.renderFooter(rows.length, totalPages);
      this.renderBulkBar();
      this.persistPreferences();
      dispatch("vh:security-table-rendered", { tableKey: this.tableKey, total: rows.length, page: this.page });
    }

    renderTable(rows, total, totalPages) {
      this.refs.table.replaceChildren();
      const thead = document.createElement("thead");
      const headerRow = document.createElement("tr");
      const selectionHeader = document.createElement("th");
      selectionHeader.scope = "col";
      const selectAll = document.createElement("input");
      selectAll.type = "checkbox";
      selectAll.setAttribute("aria-label", "Select all visible rows");
      const visibleIds = rows.map((row, index) => this.getRowId(row, index));
      const selectedVisible = visibleIds.filter((id) => this.selectedIds.has(id)).length;
      selectAll.checked = visibleIds.length > 0 && selectedVisible === visibleIds.length;
      setIndeterminate(selectAll, selectedVisible > 0 && selectedVisible < visibleIds.length);
      selectAll.disabled = visibleIds.length === 0;
      selectAll.addEventListener("change", () => {
        visibleIds.forEach((id) => (selectAll.checked ? this.selectedIds.add(id) : this.selectedIds.delete(id)));
        this.render();
        this.emitSelection();
      });
      selectionHeader.append(selectAll);
      headerRow.append(selectionHeader);
      this.visibleColumns().forEach((column) => {
        const th = document.createElement("th");
        th.scope = "col";
        th.textContent = column.label;
        if (column.sortable) {
          const sort = document.createElement("button");
          sort.type = "button";
          sort.className = "vh-security-table-sort";
          sort.textContent = this.preferences.sortId === column.id ? (this.preferences.sortDirection === "desc" ? " ↓" : " ↑") : " ↕";
          sort.setAttribute("aria-label", `Sort by ${column.label}`);
          sort.addEventListener("click", () => {
            if (this.preferences.sortId === column.id) this.preferences.sortDirection = this.preferences.sortDirection === "asc" ? "desc" : "asc";
            else {
              this.preferences.sortId = column.id;
              this.preferences.sortDirection = "asc";
            }
            this.render();
          });
          th.append(sort);
        }
        headerRow.append(th);
      });
      thead.append(headerRow);
      this.refs.table.append(thead);

      const tbody = document.createElement("tbody");
      pageRowsOrEmpty(rows, total, this.config.emptyText || "No records match the current view.").forEach((row) => {
        if (row.__empty) {
          const tr = document.createElement("tr");
          const td = document.createElement("td");
          td.colSpan = this.visibleColumns().length + 1;
          td.className = "vh-security-table-empty";
          td.textContent = row.text;
          tr.append(td);
          tbody.append(tr);
          return;
        }
        const rowId = this.getRowId(row);
        const tr = document.createElement("tr");
        tr.dataset.securityTableRow = rowId;
        const selectionCell = document.createElement("td");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = this.selectedIds.has(rowId);
        checkbox.setAttribute("aria-label", `Select ${text(this.config.rowLabel ? this.config.rowLabel(row) : rowId)}`);
        checkbox.addEventListener("click", (event) => event.stopPropagation());
        checkbox.addEventListener("change", () => {
          if (checkbox.checked) this.selectedIds.add(rowId);
          else this.selectedIds.delete(rowId);
          this.render();
          this.emitSelection();
        });
        selectionCell.append(checkbox);
        tr.append(selectionCell);
        this.visibleColumns().forEach((column) => {
          const td = document.createElement("td");
          const value = column.value ? column.value(row) : row[column.id];
          td.textContent = value === null || value === undefined || value === "" ? "—" : text(value);
          if (column.className) td.className = column.className;
          tr.append(td);
        });
        tr.addEventListener("click", () => this.openRow(row));
        tr.addEventListener("keydown", (event) => {
          if (event.key === "Enter") this.openRow(row);
        });
        tr.tabIndex = 0;
        tbody.append(tr);
        if (this.expandedId === rowId) tbody.append(this.renderExpandedRow(row));
      });
      this.refs.table.append(tbody);
    }

    renderExpandedRow(row) {
      const tr = document.createElement("tr");
      tr.className = "vh-security-table-expanded";
      const td = document.createElement("td");
      td.colSpan = this.visibleColumns().length + 1;
      const renderExpanded = this.config.renderExpanded || this.config.onRowExpand;
      const content = renderExpanded ? renderExpanded(row) : document.createTextNode("No additional row detail is available.");

      td.append(content);
      tr.append(td);
      return tr;
    }

    renderCards(rows) {
      this.refs.cards.replaceChildren();
      if (!rows.length) {
        const empty = document.createElement("p");
        empty.className = "vh-security-table-empty";
        empty.textContent = this.config.emptyText || "No records match the current view.";
        this.refs.cards.append(empty);
        return;
      }
      rows.forEach((row) => {
        const rowId = this.getRowId(row);
        const card = document.createElement("article");
        card.className = "vh-security-table-card";
        const header = document.createElement("header");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = this.selectedIds.has(rowId);
        checkbox.setAttribute("aria-label", `Select ${text(this.config.rowLabel ? this.config.rowLabel(row) : rowId)}`);
        checkbox.addEventListener("change", () => {
          if (checkbox.checked) this.selectedIds.add(rowId);
          else this.selectedIds.delete(rowId);
          this.render();
          this.emitSelection();
        });
        const title = document.createElement("strong");
        title.textContent = text(this.config.rowLabel ? this.config.rowLabel(row) : this.getRowId(row));
        header.append(checkbox, title);
        card.append(header);
        this.visibleColumns().slice(0, 5).forEach((column) => {
          const line = document.createElement("div");
          line.className = "vh-security-table-card-field";
          const label = document.createElement("small");
          label.textContent = column.label;
          const value = document.createElement("span");
          const raw = column.value ? column.value(row) : row[column.id];
          value.textContent = raw === null || raw === undefined || raw === "" ? "—" : text(raw);
          line.append(label, value);
          card.append(line);
        });
        card.addEventListener("click", () => this.openRow(row));
        this.refs.cards.append(card);
      });
    }

    renderFooter(total, totalPages) {
      this.refs.footer.replaceChildren();
      const summary = document.createElement("span");
      summary.textContent = total ? `Showing ${(this.page - 1) * this.pageSize + 1}–${Math.min(this.page * this.pageSize, total)} of ${total}` : "No matching records";
      const pageSize = document.createElement("label");
      pageSize.textContent = "Rows per page";
      const select = document.createElement("select");
      select.setAttribute("aria-label", "Rows per page");
      PAGE_SIZES.forEach((size) => {
        const option = document.createElement("option");
        option.value = String(size);
        option.textContent = String(size);
        option.selected = size === this.pageSize;
        select.append(option);
      });
      select.addEventListener("change", () => {
        this.pageSize = Number(select.value);
        this.page = 1;
        this.render();
      });
      pageSize.append(select);
      const previous = document.createElement("button");
      previous.type = "button";
      previous.className = "vh-button-secondary";
      previous.textContent = "Previous";
      previous.disabled = this.page <= 1;
      previous.addEventListener("click", () => { this.page -= 1; this.render(); });
      const next = document.createElement("button");
      next.type = "button";
      next.className = "vh-button-secondary";
      next.textContent = "Next";
      next.disabled = this.page >= totalPages;
      next.addEventListener("click", () => { this.page += 1; this.render(); });
      this.refs.footer.append(summary, pageSize, previous, next);
    }

    renderBulkBar() {
      const selected = [...this.selectedIds];
      this.refs.bulkBar.hidden = selected.length === 0;
      this.refs.bulkCount.textContent = `${selected.length} selected`;
      this.refs.bulkActions.replaceChildren();
      (this.config.bulkActions || []).forEach((action) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = action.danger ? "vh-button-danger" : "vh-button-secondary";
        button.textContent = action.label;
        button.addEventListener("click", () => action.onClick?.(selected, button, this.rows.filter((row) => selected.includes(this.getRowId(row)))));
        this.refs.bulkActions.append(button);
      });
    }

    openRow(row) {
      const rowId = this.getRowId(row);
      if (this.config.onRowOpen) {
        this.config.onRowOpen(row);
        return;
      }
      this.expandedId = this.expandedId === rowId ? null : rowId;
      this.render();
    }

    emitSelection() {
      const selected = [...this.selectedIds];
      this.config.onSelectionChange?.(selected);
      dispatch("vh:security-table-selection-change", { tableKey: this.tableKey, selectedIds: selected });
    }

    bindKeyboardShortcuts() {
      this.root.addEventListener("keydown", (event) => {
        if (isField(event.target)) return;
        if (event.key === "/") {
          event.preventDefault();
          this.refs.search?.focus();
        }
      });
    }
  }

  const pageRowsOrEmpty = (rows, total, emptyText) => rows.length ? rows : [{ __empty: true, text: total ? "No records match the current view." : emptyText }];

  const mount = (root, config) => new SecurityTable(root, config).mount();

  const mountExisting = (root, config = {}) => {
    const table = root.querySelector("table");
    if (!table) return null;
    const headers = [...table.querySelectorAll("thead th")].map((header, index) => ({
      id: header.dataset.columnId || `column_${index}`,
      label: header.textContent.trim() || `Column ${index + 1}`,
      visibleByDefault: header.dataset.mobileHidden !== "true",
      critical: header.dataset.critical === "true",
      sortable: header.dataset.sortable === "true",
    }));
    const rows = [...table.querySelectorAll("tbody tr")].map((row, rowIndex) => {
      const cells = [...row.children];
      const values = {};
      headers.forEach((column, index) => {
        values[column.id] = cells[index]?.textContent.trim() || "";
      });
      values.__rowHref = row.querySelector("a[href]")?.href || "";
      values.__rowIndex = rowIndex;
      return values;
    });
    const rowLabel = (row) => row[headers[0]?.id] || row.__rowIndex;
    return mount(root, {
      ...config,
      rows,
      columns: headers,
      rowLabel,
      onRowOpen: (row) => {
        if (row.__rowHref) window.location.assign(row.__rowHref);
      },
    });
  };

  const bootExisting = () => {
    document.querySelectorAll("[data-security-table]").forEach((root) => {
      if (root.dataset.securityTableHydrated === "true") return;
      root.dataset.securityTableHydrated = "true";
      mountExisting(root, {
        tableKey: root.dataset.securityTable,
        title: root.dataset.securityTableTitle,
        description: root.dataset.securityTableDescription,
        emptyText: root.dataset.securityTableEmpty,
        filters: (() => {
          if (!root.dataset.securityTableFilters) return [];
          try { return JSON.parse(root.dataset.securityTableFilters); } catch (_error) { return []; }
        })(),
      });
    });
  };

  window.VulnHunterSecurityTable = Object.freeze({ SecurityTable, mount, mountExisting, labelize });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bootExisting);
  else bootExisting();
})();
