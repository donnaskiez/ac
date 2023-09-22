using server.Database.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database.Entity.Report.Types
{
    public class InvalidProcessAllocationEntity : ReportTypeInvalidProcessAllocation, IReportEntity
    {
        private readonly ModelContext _modelContext;
        public ReportEntity ReportEntity { get; set; }

        public InvalidProcessAllocationEntity(ModelContext modelContext)
        {
            ReportEntity = new ReportEntity(modelContext);
            _modelContext = modelContext;
        }

        public void InsertReport()
        {
            _modelContext.ReportTypeInvalidProcessAllocation.Add(this);
        }
    }
}
