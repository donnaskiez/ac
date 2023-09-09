using Microsoft.Extensions.Logging;
using server.Types.ClientReport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database
{
    public class ClientSend
    {
        private ILogger _logger;

        private enum ClientSendCodes
        {
            MODULE_VERIFICATION_CHECKSUM_FAILURE = 10,
        }

        public ClientSend(ILogger<ClientSend> logger)
        {
            _logger = logger;
        }

        public void InsertReport<T>(T report, int reportCode)
        {
            if (report == null)
            {
                _logger.LogError("Report is null");
                return;
            }

            switch (reportCode)
            {
/*                case (int)ReportCodes.MODULE_VERIFICATION_CHECKSUM_FAILURE:
                    InsertReportWithCode10((MODULE_VERIFICATION_CHECKSUM_FAILURE)Convert.ChangeType(report, typeof(MODULE_VERIFICATION_CHECKSUM_FAILURE)));
                    break;
                default:
                    _logger.LogError("Unknown report code: {0}", reportCode);
                    break;*/
            }
        }

        private void InsertReportWithCode10(MODULE_VERIFICATION_CHECKSUM_FAILURE report)
        {

        }
    }
}
