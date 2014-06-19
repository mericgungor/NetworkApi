using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace NetworkApi.Web
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string script="<script type=\"text/javascript\" src=\"http://l2.io/ip.js?var=myip\"></script>";
            
            NetworkApi.Business.Utilty.RegisterClientScriptBlock(this,script,false);

        }
    }
}