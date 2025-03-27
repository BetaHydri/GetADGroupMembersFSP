using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks.Dataflow;

namespace GetADGroupMembersFSP
{
    class Program
    {
        static int Main(string[] args)
        {
            RootCommand rootCommand = new RootCommand
            {
                new Option<string>(
                    "--group-name",
                    "The name of the Active Directory group"),
                new Option<bool>(
                    "--recursive",
                    "Whether to retrieve members recursively"),
                new Option<string>(
                    "--output-csv-file",
                    "The path to the output CSV file"),
                new Option<string>(
                    "--csv-delimiter",
                    () => ",",
                    "The delimiter to use in the CSV file"),
                new Option<bool>(
                    "--debug",
                    "Enable debug output"),
            };

            rootCommand.Description = "GetADGroupMembersFSP - A tool to retrieve members of an Active Directory group and export them to a CSV file.";

            rootCommand.Handler = CommandHandler.Create<string, bool, string, string, bool>((groupName, recursive, outputCsvFile, csvDelimiter, debug) =>
            {
                // Ensure the debug parameter is passed correctly
                if (debug)
                {
                    Console.WriteLine("Debug mode enabled.");
                }

                if (string.IsNullOrEmpty(groupName))
                {
                    Console.WriteLine("GroupName is required.");
                    return;
                }

                PrincipalContext ctx;

                try
                {
                    // Use current Windows identity
                    string currentDomain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
                    ctx = new PrincipalContext(ContextType.Domain, currentDomain);
                    if (debug) {
                        Console.WriteLine("PrincipalContext created successfully using current Windows identity.");
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error: Unable to connect to Active Directory. {ex.Message}");
                    Console.ResetColor();
                    return;
                }

                // Call the method to get group members
                List<GroupMember> members = GetGroupMembers(groupName, recursive, ctx, debug);

                // Export to CSV if specified
                if (!string.IsNullOrEmpty(outputCsvFile))
                {
                    try
                    {
                        ExportToCsv(members, outputCsvFile, csvDelimiter);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Unauthorized access error: {ex.Message}");
                        Console.ResetColor();
                        return;
                    }
                }

                // Display the results
                Console.WriteLine($"Domain Name: {GetDomainName()}");
                Console.WriteLine($"Group Name: {groupName}");

                // Calculate the total members count correctly
                int totalMembers = members.Count;
                // Ensure MembersCount is calculated correctly and DirectGroups includes all groups
                var uniqueMembers = members
                    .GroupBy(m => m.DistinguishedName)
                    .Select(g => new
                    {
                        Member = g.First(),
                        Count = g.Sum(m => m.DirectGroups.Count) // Sum all DirectGroups for accurate MembersCount
                    })
                    .ToList();

                // Update DirectGroups to include all groups where the AD object is a member
                foreach (var member in uniqueMembers)
                {
                    member.Member.DirectGroups = members
                        .Where(m => m.DistinguishedName == member.Member.DistinguishedName)
                        .SelectMany(m => m.DirectGroups)
                        .Distinct()
                        .ToList();
                }

                // Update total members to reflect the MembershipCount in CSV output
                totalMembers = uniqueMembers.Sum(m => m.Count); // Sum the MembershipCount property for accurate total
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Total Members: {totalMembers}");
                Console.WriteLine($"Unique Members: {uniqueMembers.Count}");
                Console.ResetColor();

                int maxDistinguishedNameLength = uniqueMembers.Any() ? uniqueMembers.Max(m => m.Member.DistinguishedName.Length) : 0;
                int maxObjectClassLength = uniqueMembers.Any() ? uniqueMembers.Max(m => m.Member.ObjectClass.Length) : 0;
                int maxNTAccountNameLength = uniqueMembers.Any() ? uniqueMembers.Max(m => m.Member.NTAccount.Length) : 0;
                int maxDirectGroupsLength = uniqueMembers.Any() ? uniqueMembers.Max(m => string.Join(", ", m.Member.DirectGroups).Length) : 0;

                if (totalMembers > 0)
                {
                    Console.WriteLine($"| {"NTAccountName".PadRight(maxNTAccountNameLength)} | {"Class".PadRight(maxObjectClassLength)} | MembersCount   | {"DirectGroups".PadRight(maxDirectGroupsLength)} |");
                    Console.WriteLine($"|{new string('-', maxNTAccountNameLength + 2)}|{new string('-', maxObjectClassLength + 2)}|----------------|{new string('-', maxDirectGroupsLength + 2)}|");
                    foreach (var member in uniqueMembers)
                    {
                        if (member.Count > 1)
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                        }
                        Console.WriteLine($"| {member.Member.NTAccount.PadRight(maxNTAccountNameLength)} | {member.Member.ObjectClass.PadRight(maxObjectClassLength)} | {member.Count.ToString().PadRight(14)} | {string.Join(", ", member.Member.DirectGroups).PadRight(maxDirectGroupsLength)} |");
                    }

                    // Reset the console color
                    Console.ResetColor();
                }
                else
                {
                    Console.WriteLine("No members found in the specified group.");
                }
            });

            return rootCommand.InvokeAsync(args).Result;
        }

        static List<GroupMember> GetGroupMembers(string groupName, bool recursive, PrincipalContext ctx, bool debug)
        {
            List<GroupMember> members = new List<GroupMember>();

            try
            {
            // Get the distinguished name of the group
            string groupDistinguishedName = GetGroupDistinguishedName(groupName, ctx);

            if (string.IsNullOrEmpty(groupDistinguishedName))
            {
                Console.WriteLine($"Group '{groupName}' not found in Active Directory.");
                return members;
            }
            if (debug) {
                Console.WriteLine($"Distinguished Name of the group: {groupDistinguishedName}");
            }
            // Use ADSI LDAP to retrieve group members
            using (DirectoryEntry groupEntry = new DirectoryEntry($"LDAP://{ctx.ConnectedServer}/{groupDistinguishedName}"))
            {
                RetrieveGroupMembersRecursive(groupEntry, members, recursive, debug);
            }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error retrieving group members: {ex.Message}");
                Console.ResetColor();
            }

            return members;
        }

        static void RetrieveGroupMembersRecursive(DirectoryEntry groupEntry, List<GroupMember> members, bool recursive, bool debug)
        {
            try
            {
            PropertyValueCollection memberProperty = groupEntry.Properties["member"];
            if (memberProperty != null)
            {
                foreach (var memberDn in memberProperty)
                {
                if (memberDn.ToString().Contains("CN=ForeignSecurityPrincipal"))
                {
                    try
                    {
                        // Extract the SID from the DN
                        string sidString = memberDn.ToString().Split(',')[0].Substring(3); // Extract "S-1-5-21-..."
                        SecurityIdentifier sid = new SecurityIdentifier(sidString);

                        // Translate the SID to an NTAccount
                        NTAccount ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                        string ntAccountName = ntAccount.Value;
                        if (debug) {
                            Console.WriteLine($"Resolved NTAccountName: {ntAccountName}");
                        }
                        // Extract the domain part of the NTAccountName
                        string domain = ntAccountName.Split('\\')[0];
                        if (debug) {
                            Console.WriteLine($"Domain of ForeignSecurityPrincipal: {domain}");
                        }
                        // Prompt for credentials for the foreign domain
                        Console.WriteLine($"Authentication required for domain: {domain}");
                        Console.Write("Enter username for foreign domain: ");
                        string username = Console.ReadLine();

                        Console.Write("Enter password for foreign domain: ");
                        string password = ReadPassword();

                        // Validate credentials and add the member
                        using (PrincipalContext foreignCtx = new PrincipalContext(ContextType.Domain, domain, username, password))
                        {
                            if (foreignCtx.ValidateCredentials(username, password))
                            {
                                Console.WriteLine("Credentials validated successfully for foreign domain.");

                                using (GroupPrincipal foreignGroup = GroupPrincipal.FindByIdentity(foreignCtx, ntAccountName))
                                {
                                    if (foreignGroup != null)
                                    {
                                        if (debug) {
                                            Console.WriteLine($"ForeignSecurityPrincipal is a group: {foreignGroup.Name}");
                                        }
                                        if (recursive)
                                        {
                                            if (debug) {
                                                Console.WriteLine($"Recursively retrieving members of foreign group: {foreignGroup.Name}");
                                            }
                                            GetGroupMembersRecursive(foreignGroup, members, null, debug);
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("ForeignSecurityPrincipal is not a group.");
                                    }
                                }
                            }
                            else
                            {
                                
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("Invalid credentials for the foreign domain.");
                                Console.ResetColor();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Error resolving ForeignSecurityPrincipal: {ex.Message}");
                        Console.ResetColor();
                    }
                }
                else
                {
                    if (debug) {
                        Console.WriteLine($"Found member: {GetGroupNameFromDistinguishedName(memberDn.ToString())}");
                    }
                }

                using (DirectoryEntry memberEntry = new DirectoryEntry($"LDAP://{memberDn}"))
                {
                    string objectClass = memberEntry.SchemaClassName;
                    string distinguishedName = memberEntry.Properties["distinguishedName"].Value.ToString();

                    GroupMember member = new GroupMember
                    {
                    DistinguishedName = distinguishedName,
                    ObjectClass = objectClass,
                    NTAccount = ResolveNTAccountFromDistinguishedName(distinguishedName),
                    DirectGroups = new List<string> { groupEntry.Properties["name"].Value.ToString() } // Use SamAccountName or name
                    };

                    // Ensure the DirectGroups property includes the initial group for user objects
                    if (!member.DirectGroups.Contains(groupEntry.Properties["name"].Value.ToString()))
                    {
                        member.DirectGroups.Add(groupEntry.Properties["name"].Value.ToString());
                    }

                    members.Add(member);

                    // If recursive and the member is a group, retrieve its members
                    if (recursive && objectClass.Equals("group", StringComparison.OrdinalIgnoreCase))
                    {
                     if (debug) {
                        Console.WriteLine($"Recursively retrieving members of nested group: {GetGroupNameFromDistinguishedName(distinguishedName)}");
                     }
                    RetrieveGroupMembersRecursive(memberEntry, members, recursive, debug);
                    }
                }
            }
        }
            else
            {
                Console.WriteLine("No members found in the group.");
            }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error retrieving members recursively: {ex.Message}");
                Console.ResetColor();
            }
        }

        static void GetGroupMembersRecursive(GroupPrincipal group, List<GroupMember> members, List<string> parentGroups, bool debug)
        {
            if (parentGroups == null)
            {
                parentGroups = new List<string>();
            }
            parentGroups.Add(group.Name);

            string initialGroupDomain = ParseDomainFromDistinguishedName(group.DistinguishedName);

            foreach (Principal p in group.GetMembers())
            {
                try
                {
                    string memberDomain = ParseDomainFromDistinguishedName(p.DistinguishedName);

                    if (!string.Equals(initialGroupDomain, memberDomain, StringComparison.OrdinalIgnoreCase) || p.StructuralObjectClass == "foreignsecurityprincipal")
                    {
                        Console.WriteLine($"Foreign member or placeholder detected: {p.DistinguishedName} from domain {memberDomain}");
                        HandleForeignSecurityPrincipal(p.DistinguishedName, members, group.Name, true, debug);
                        continue;
                    }

                    GroupMember member = members.FirstOrDefault(m => m.DistinguishedName == p.DistinguishedName);
                    if (member == null)
                    {
                        member = CreateGroupMember(p, group.Name);
                        members.Add(member);
                    }
                    else
                    {
                        member.DirectGroups.Add(group.Name);
                    }

                    if (p is GroupPrincipal nestedGroup)
                    {
                        if (debug)
                        {
                            Console.WriteLine("Debug: Retrieving nested group members.");
                            Console.WriteLine($"Recursively retrieving members of nested group: {nestedGroup.Name}");
                        }
                        GetGroupMembersRecursive(nestedGroup, members, parentGroups, debug);
                    }
                }
                catch (System.Security.Authentication.AuthenticationException ex)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"Authentication error for member: {p.Name}. {ex.Message}");
                    Console.WriteLine("Prompting for credentials for the foreign domain...");
                    Console.ResetColor();

                    // Prompt for credentials and handle the foreign security principal
                    HandleForeignSecurityPrincipal(p.DistinguishedName, members, group.Name, true, debug);
                }
                catch (PrincipalOperationException ex)
                {
                    Console.WriteLine($"Error retrieving member: {p.Name}. {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Unexpected error retrieving member: {p.Name}. {ex.Message}");
                    Console.ResetColor();
                }
            }
            parentGroups.Remove(group.Name);
        }

        static GroupMember CreateGroupMember(Principal principal, string groupName)
        {
            var member = new GroupMember
            {
                DistinguishedName = principal.DistinguishedName,
                ObjectClass = principal.StructuralObjectClass,
                NTAccount = principal.StructuralObjectClass == "foreignsecurityprincipal" ? PromptForForeignSecurityPrincipalCredentials(principal) : ResolveNTAccount(principal),
                DirectGroups = new List<string> { groupName }
            };
            return member;
        }

        static string PromptForForeignSecurityPrincipalCredentials(Principal principal)
        {
            if (principal is AuthenticablePrincipal authPrincipal)
            {
                SecurityIdentifier sid = authPrincipal.Sid;
                try
                {
                    Console.WriteLine("ForeignSecurityPrincipal detected. Please provide credentials for the trusted domain.");

                    // Parse the domain from the DistinguishedName
                    string domain = ParseDomainFromDistinguishedName(principal.DistinguishedName);
                    Console.WriteLine($"Domain: {domain}");

                    Console.Write("Enter username: ");
                    string username = Console.ReadLine();

                    Console.Write("Enter password: ");
                    string password = ReadPassword();

                    // Attempt to resolve the NTAccount using the provided credentials
                    try
                    {
                        using (var ctx = new PrincipalContext(ContextType.Domain, domain, username, password))
                        {
                            if (ctx.ValidateCredentials(username, password))
                            {
                                NTAccount ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                                return ntAccount.Value;
                            }
                            else
                            {
                                Console.WriteLine("Invalid credentials for the trusted domain.");
                                return "Unresolved NTAccount";
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Error resolving ForeignSecurityPrincipal: {ex.Message}");
                        Console.ResetColor();
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error resolving ForeignSecurityPrincipal: {ex.Message}");
                    Console.ResetColor();
                }
            }
            return "Unknown NTAccount";
        }

        static string ResolveNTAccount(Principal principal)
        {
            if (principal is UserPrincipal user)
            {
                return $"{GetNetBIOSDomainName(user.Context)}\\{user.SamAccountName}";
            }
            else if (principal is GroupPrincipal group)
            {
                return $"{GetNetBIOSDomainName(group.Context)}\\{group.SamAccountName}";
            }
            else if (principal is AuthenticablePrincipal authPrincipal)
            {
                SecurityIdentifier sid = authPrincipal.Sid;
                try
                {
                    NTAccount ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                    return ntAccount.Value;
                }
                catch (Exception)
                {
                    return "Unresolved NTAccount";
                }
            }
            return "Unknown NTAccount";
        }

        static string GetNetBIOSDomainName(PrincipalContext context)
        {
            using (DirectorySearcher searcher = new DirectorySearcher(new DirectoryEntry("LDAP://" + context.ConnectedServer)))
            {
                searcher.Filter = "(objectClass=domain)";
                searcher.PropertiesToLoad.Add("name");
                SearchResult result = searcher.FindOne();
                if (result != null)
                {
                    return result.Properties["name"][0].ToString();
                }
            }
            return "UnknownDomain";
        }

        static void ExportToCsv(List<GroupMember> members, string filePath, string delimiter)
        {
            var uniqueMembers = members
                .GroupBy(m => m.DistinguishedName)
                .Select(g => new
                {
                    Member = g.First(),
                    Count = g.First().DirectGroups.Count
                })
                .ToList();

            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine($"DistinguishedName{delimiter}ObjectClass{delimiter}NTAccountName{delimiter}MembershipCount{delimiter}DirectGroups");
                foreach (var member in uniqueMembers)
                {
                    writer.WriteLine($"{member.Member.DistinguishedName}{delimiter}{member.Member.ObjectClass}{delimiter}{member.Member.NTAccount}{delimiter}{member.Count}{delimiter}{string.Join("|", member.Member.DirectGroups)}");
                }
            }
        }

        static string GetDomainName()
        {
            try
            {
                return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error retrieving domain name: {ex.Message}");
                Console.ResetColor();
                // Return a default value or handle the error as needed
                return "Unknown Domain";
            }
        }

        static string ReadPassword()
        {
            string password = string.Empty;
            ConsoleKeyInfo info;
            do
            {
                info = Console.ReadKey(true);
                if (info.Key != ConsoleKey.Backspace && info.Key != ConsoleKey.Enter)
                {
                    password += info.KeyChar;
                    Console.Write("*");
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        password = password.Substring(0, password.Length - 1);
                        Console.Write("\b \b");
                    }
                }
            } while (info.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return password;
        }

        static string ParseDomainFromDistinguishedName(string distinguishedName)
        {
            // Extract the domain components (DC=...) from the DistinguishedName
            string[] domainComponents = distinguishedName.Split(',')
                .Where(part => part.TrimStart().StartsWith("DC="))
                .Select(part => part.Substring(3))
                .ToArray();

            // Join the domain components to form the domain name
            return string.Join(".", domainComponents);
        }

        static void HandleForeignSecurityPrincipal(string distinguishedName, List<GroupMember> members, string parentGroupName, bool recursive, bool debug)
        {
            try
            {
                // Extract the SID from the DN
                string sidString = distinguishedName.Split(',')[0].Substring(3); // Extract "S-1-5-21-..."
                string ntAccountName = ResolveNTAccountNameUsingDirectoryServices(sidString);

                if (string.IsNullOrEmpty(ntAccountName))
                {
                    Console.WriteLine($"Unable to resolve NTAccountName for SID: {sidString}");
                    return;
                }
                if (debug)
                {
                    Console.WriteLine($"Resolved NTAccountName: {ntAccountName}");
                }
                // Extract the domain part of the NTAccountName
                string domain = ntAccountName.Split('\\')[0];
                if (debug) {
                    Console.WriteLine($"Domain of ForeignSecurityPrincipal: {domain}");
                }
                // Prompt for credentials for the foreign domain
                Console.WriteLine($"Authentication required for domain: {domain}");
                Console.Write("Enter username for foreign domain: ");
                string username = Console.ReadLine();

                Console.Write("Enter password for foreign domain: ");
                string password = ReadPassword();

                // Validate credentials and add the member
                using (PrincipalContext foreignCtx = new PrincipalContext(ContextType.Domain, domain, username, password))
                {
                    if (foreignCtx.ValidateCredentials(username, password))
                    {
                    Console.WriteLine("Credentials validated successfully for foreign domain.");

                    using (GroupPrincipal foreignGroup = GroupPrincipal.FindByIdentity(foreignCtx, ntAccountName))
                    {
                        if (foreignGroup != null)
                        {
                        Console.WriteLine($"ForeignSecurityPrincipal is a group: {foreignGroup.Name}");

                        if (recursive)
                        {
                            if (debug)
                            {
                            Console.WriteLine($"Recursively retrieving members of foreign group: {foreignGroup.Name}");
                            }
                            GetGroupMembersRecursive(foreignGroup, members, null, debug);
                        }
                        }
                        else
                        {
                        Console.WriteLine("ForeignSecurityPrincipal is not a group.");
                        }
                    }
                    }
                    else
                    {
                    Console.WriteLine("Invalid credentials for the foreign domain.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error handling ForeignSecurityPrincipal: {ex.Message}");
                Console.ResetColor();
            }
        }

        static string ResolveNTAccountNameUsingDirectoryServices(string sidString)
        {
            try
            {
                // Convert the SID string to a SecurityIdentifier object
                SecurityIdentifier sid = new SecurityIdentifier(sidString);

                // Translate the SID to an NTAccount
                NTAccount ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                return ntAccount.Value;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error resolving SID to NTAccountName: {ex.Message}");
                Console.ResetColor();
                return null;
            }
        }

        static string GetGroupDistinguishedName(string groupName, PrincipalContext ctx)
        {
            using (DirectorySearcher searcher = new DirectorySearcher(new DirectoryEntry($"LDAP://{ctx.ConnectedServer}")))
            {
                searcher.Filter = $"(&(objectClass=group)(cn={groupName}))";
                searcher.PropertiesToLoad.Add("distinguishedName");

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties["distinguishedName"].Count > 0)
                {
                    return result.Properties["distinguishedName"][0].ToString();
                }
            }
            return null;
        }

        static string GetObjectClass(string distinguishedName)
        {
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{distinguishedName}"))
                {
                    return entry.SchemaClassName;
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        static string ResolveNTAccountFromDistinguishedName(string distinguishedName)
        {
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{distinguishedName}"))
                {
                    SecurityIdentifier sid = new SecurityIdentifier((byte[])entry.Properties["objectSid"][0], 0);
                    NTAccount ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                    return ntAccount.Value;
                }
            }
            catch
            {
                return "Unresolved NTAccount";
            }
        }

        static string GetGroupNameFromDistinguishedName(string distinguishedName)
        {
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{distinguishedName}"))
                {
                    return entry.Properties["cn"].Value.ToString();
                }
            }
            catch
            {
                return "Unknown Group";
            }
        }
    }

    class GroupMember
    {
        public string DistinguishedName { get; set; }
        public string ObjectClass { get; set; }
        public string NTAccount { get; set; }
        public List<string> DirectGroups { get; set; } = new List<string>();
    }
}