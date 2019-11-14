using Northwind.Models;
using System.Collections.Generic;

namespace Northwind.Repositories
{
    public interface ICustomerRepository: IRepository<Customer>
    {
        IEnumerable<Customer> CustomerPageList(int page, int rows);
    }
}
