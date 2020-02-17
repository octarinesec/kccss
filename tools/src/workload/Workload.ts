import {Risk, scopeImpact} from "../rules/Risk"
import {Remediation} from "../rules/Remediation"



export class Workload {
    risks: Risk[] = [];
    remediations: Remediation[] = [];
    score: number = 0;

    public addRisk(risk: Risk) {
        for(var i in this.risks) {
            if (this.risks[i].id == risk.id) {
                console.log(`Skip risk ${risk.id} - ${risk.name}`);
                return;
            }
        }

        this.risks.push(risk);
    }

    public addRemediation(remediation: Remediation) {
        for(var i in this.remediations) {
            if (this.remediations[i].id == remediation.id) {
                return;
            }
        }

        this.remediations.push(remediation)
    }

    public computeScore() : number {
        var elements : any = {}

        // find the max scores for AttackVector/Scope
        for(var i in this.risks) {
            var risk : Risk = this.risks[i];

            var av = risk.attackVector.impact;
            var s = risk.scope.impact

            var key = av.valueOf() + s.valueOf();

            if (! elements.hasOwnProperty(key)) {
                elements[key] = risk;
                console.log(`Add risk ${risk.title}`);
            }
            else if (elements[key].id != risk.id && elements[key].score < risk.score) {
                console.log(`Skip risk ${elements[key].title} (${elements[key].id}) - ejected by ${risk.title} (${risk.id})`);

                elements[key] = risk;
            }      
            else if (elements[key].id != risk.id) {
                console.log(`Skip risk ${risk.title} (${risk.id}) because of ${elements[key].title}`);
            }      
        }

        var exclude : any = {};
        var keys = Object.keys(elements);
        for(var i in keys) {
            var key = keys[i];
            var risk : Risk = elements[key];

            if (risk.scope.impact == scopeImpact.None) {
                // N matches H and C
                var h = null;
                var c = null;

                for(var j in keys) {
                    var newKey = keys[j];
                    var newRisk : Risk = elements[newKey];
                    
                    if (risk.id != newRisk.id && risk.attackVector.impact == newRisk.attackVector.impact) {
                        if (newRisk.scope.impact == scopeImpact.Host && h == null) {
                             h = newRisk; // there should ne only 1 instance
                        }
                        else if (newRisk.scope.impact == scopeImpact.Cluster && c == null) {
                            c = newRisk;
                        }
                    }

                    if (c == null || h == null) {
                        // Only take the max

                        if (c != null && risk.score > c.score) {
                            exclude[c.id] = c.id;
                        }
                        else if (h != null && risk.score > h.score) {
                            exclude[h.id] = h.id;
                        }
                    }
                    else {
                        // Take C + H, or N
                        const combinedScore = Math.sqrt(Math.pow(c.score, 2) + Math.pow(h.score, 2));

                        if (combinedScore > risk.score) {
                            exclude[risk.id] = risk.id;
                        }
                        else {
                            exclude[c.id] = c.id;
                            exclude[h.id] = h.id;
                        }
                    }
                }

            }
        }

        // Compute the score, skip the excluded risks
        var score = 0;
        for(var i in keys) {
            var key = keys[i];
            var risk : Risk = elements[key];

            if (exclude.hasOwnProperty(risk.id)) {
                continue;
            }

            score += Math.pow(risk.score, 2);
        }

        this.score = Math.sqrt(score);

        return this.score;
    }

    /*getModifiedRisk(risk: Risk) : Risk {
        // find matching remediation

        
    }*/
}