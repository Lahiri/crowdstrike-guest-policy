# Configuration MonitorAntivirus
# {
#     Import-DscResource -ModuleName C:\Dev\Customer\Zurich\crowdstrike-policy\EndPointProtectionDSC.psd1 #EndPointProtectionDSC

#     Node localhost
#     {

#         FalconStatus AV
#         {
#             Status        = "Running"
#             Ensure        = "Present"
#         }
#     }
# }

# #cd $env:Temp
# MonitorAntivirus

Configuration MyConfig {
    Import-DSCResource -module Modules\CheckCrowdStrike\CheckCrowdStrike.psd1
    CheckCrowdStrike localhost {
        Name = "Crowdsrike"
        Status = "Running"
        Ensure = "Present"
    }
}

MyConfig