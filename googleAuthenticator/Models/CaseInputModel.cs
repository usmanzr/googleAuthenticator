using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace googleAuthenticator.Models
{
    public class CaseInputModel
    {
        public string CaseNumber { get; set; }
        public string InformantID { get; set; }
        public string PoliceBadgeID { get; set; }
        public string ProtectedAddress { get; set; }
    }
}