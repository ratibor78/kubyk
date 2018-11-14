

$(document).ready( function () {
      $('#dataTable').DataTable( {
            "order": [[ 1, "desc" ]],
            "pageLength": 10,
          });
      var table = $('#dataTable').DataTable();

      $('#dataTable tbody').on('click', 'tr', function () {
          var data = table.row( this ).data();
          alert( 'You clicked on '+data[0]+' row' );
        } );
      } );
