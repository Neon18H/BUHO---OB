(function(){
  window.Buho = {
    severityBadgeClass: function(level){ return 'badge-sev-' + String(level||'LOW').toUpperCase(); }
  };
  document.addEventListener('DOMContentLoaded', function(){
    if (window.jQuery && jQuery.fn.DataTable) {
      document.querySelectorAll('table[data-datatable="true"]').forEach(function(table){
        if (!jQuery.fn.DataTable.isDataTable(table)) {
          jQuery(table).DataTable({ pageLength: 25, order: [] });
        }
      });
    }
  });
})();
