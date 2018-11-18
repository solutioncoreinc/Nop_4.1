namespace Nop.Plugin.Api.Controllers.Account
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    public class LogoutInputModel
    {
        public string LogoutId { get; set; }

        public string ReturnUrl { get; set; }
    }
}
