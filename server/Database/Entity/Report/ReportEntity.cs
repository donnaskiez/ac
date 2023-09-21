using server.Database.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database.Entity.Report
{
    public class ReportEntity : Model.Report
    {
        private readonly ModelContext _modelContext;
        private UserEntity UserEntity { get; set; }

        public ReportEntity(ModelContext modelContext)
        {
            UserEntity = new UserEntity(modelContext);
            _modelContext = modelContext;
        }

        public void InsertReport()
        {
            _modelContext.Reports.Add(this);
        }
    }
}
