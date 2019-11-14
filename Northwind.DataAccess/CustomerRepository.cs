using System.Collections.Generic;
using System.Data.SqlClient;
using Dapper;
using Northwind.Models;
using Northwind.Repositories;

namespace Northwind.DataAccess
{
    public class CustomerRepository: Repository<Customer>, ICustomerRepository
    {
        public CustomerRepository( string connectionStrng):base(connectionStrng)
        {
        
        }

        public IEnumerable<Customer> CustomerPageList(int page, int rows)
        {
            var parameters = new DynamicParameters();
            parameters.Add("@page", page);
            parameters.Add("@rows", rows);

            using(var connection = new SqlConnection(_connectionString))
            {
                return connection.Query<Customer>("dbo.CustomerPagedList",
                    parameters,
                    commandType: System.Data.CommandType.StoredProcedure);
            }
        }
    }
}
