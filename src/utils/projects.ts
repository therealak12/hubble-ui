import axios from 'axios';

export interface user {
  username: string;
  projects: Array<string>;
}

export class Projects {
  private static instance: Projects;

  private projects: Array<string> | null = null;

  public static getInstance(): Projects {
    if (!Projects.instance) {
      Projects.instance = new Projects();
    }

    return Projects.instance;
  }

  getProjects(): Array<string> | null {
    return this.projects;
  }

  manipulateUrl(url: string): string {
    const regex = /hubble/;
    const match: boolean = regex.test(url);
    if (match) {
      return url.replace('hubble', 'hubble-middleware');
    }
    return url;
  }

  async setProjects(token: string) {
    const headers = {
      Authorization: 'Bearer ' + token,
    };

    const baseUrl = this.manipulateUrl(window.location.origin);

    const url = baseUrl + '/projects';

    const res = await axios.get<user>(url, { headers });

    console.log(res.data.projects);
    console.log(res.data.toString());
    this.projects = res.data.projects;
  }
}
