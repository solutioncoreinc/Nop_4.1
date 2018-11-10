using System;
using System.Collections.Generic;
using System.Text;

namespace Nop.Plugin.Api.Models.Account
{
    public class ExternalProvider
    {
        public string DisplayName { get; set; }
        public string AuthenticationScheme { get; set; }
    }
}
