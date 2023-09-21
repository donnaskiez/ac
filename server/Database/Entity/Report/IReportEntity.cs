using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database.Entity.Report
{
    /// <summary>
    /// Implements the IReport interface
    /// </summary>
    public interface IReportEntity
    {   
        /// <summary>
        /// Inserts the report into the database.
        /// </summary>
        void InsertReport();
    }
}
