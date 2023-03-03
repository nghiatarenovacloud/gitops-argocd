variable "scp" {
  type = map(any)
  default = {
    "PreventRootactivity" : {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Deny",
          "Action" : "*",
          "Resource" : "arn:aws:iam::*:root"
        }
      ]
    },
    "PreventRootactivity1" : {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Deny",
          "Action" : "*",
          "Resource" : "arn:aws:iam::*:root"
        }
      ]
    }
  }
}


