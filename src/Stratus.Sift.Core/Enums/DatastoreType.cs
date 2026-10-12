using System.Text.Json.Serialization;

namespace Stratus.Sift.Core.Enums;

[JsonConverter(typeof(JsonStringEnumConverter<DatastoreType>))]
public enum DatastoreType
{
    Unknown = 0,
    SharePoint = 1,
    OneDrive = 2,
    Teams = 3,
    Exchange = 4,
    Dynamics = 5,
    PowerBI = 6,
    Dropbox = 7,
    GoogleDrive = 8,
    Box = 9,
    FileSystem = 10,
    AzureBlob = 11,
    AzureFileShare = 12,
    Slack = 13,
    Jira = 14,
    Confluence = 15,
    Planner = 16,
    ToDo = 17,
    OneNote = 18,
    VivaEngage = 19
}
