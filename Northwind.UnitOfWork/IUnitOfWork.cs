using Northwind.Repositories;
using System;
using System.Collections.Generic;
using System.Text;

namespace Northwind.UnitOfWork
{
    public interface IUnitOfWork
    {
        ICustomerRepository Customer { get; }
    }
}
