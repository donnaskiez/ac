using server.Database.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database.Entity.Report
{
    public class Report
    {
        private readonly ModelContext _modelContext;
        public UserEntity UserEntity { get; set; }

        public Report(ModelContext modelContext)
        {
            UserEntity = new UserEntity(modelContext);
            _modelContext = modelContext;
        }
    }
}
