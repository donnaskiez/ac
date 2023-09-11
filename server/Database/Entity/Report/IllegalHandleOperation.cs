using server.Database.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database.Entity.Report
{
    public class IllegalHandleOperationEntity : ReportIllegalHandleOperation, IReport
    {
        private readonly ModelContext _modelContext;
        public UserEntity UserEntity { get; set; }

        public IllegalHandleOperationEntity(ModelContext modelContext)
        {
            UserEntity = new UserEntity(modelContext);
            _modelContext = modelContext;
        }

        public void InsertReport()
        {
            _modelContext.ReportIllegalHandleOperation.Add(this);
        }
    }
}
